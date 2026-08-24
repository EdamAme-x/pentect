use fancy_regex::Regex as FancyRegex;
use prost::Message;
use serde::Deserialize;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use tract_onnx::pb::{self, tensor_proto};

const ML_CONFIG_JSON: &str =
    include_str!("../../vendors/credsweeper-assets/ml_model/ml_config.json");
const ML_MODEL_ONNX: &[u8] =
    include_bytes!("../../vendors/credsweeper-assets/ml_model/ml_model.onnx");
const MORPHEME_CHECKLIST: &str =
    include_str!("../../vendors/credsweeper-assets/common/morpheme_checklist.txt");

const ML_HUNK: usize = 64;
const MAX_LEN: usize = 2 * ML_HUNK;
const MIN_DATA_LEN: usize = 8;
const CHUNK_SIZE: usize = 4000;
const ZERO_CHAR: char = '\0';
const FAKE_CHAR: char = '\x01';

thread_local! {
    static VALIDATOR: RefCell<MlValidator> = RefCell::new(
        MlValidator::compile().expect("embedded CredSweeper ML assets compile")
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RuleSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Clone, Debug)]
pub(super) struct MlInput {
    pub line: String,
    pub value: String,
    pub variable: String,
    pub value_start: usize,
    pub value_end: usize,
    pub variable_start: isize,
    pub variable_end: isize,
    pub path: String,
    pub line_num: usize,
    pub file_type: String,
    pub rule_name: String,
    pub severity: RuleSeverity,
}

pub(super) fn accept_group(group: &[&MlInput]) -> bool {
    VALIDATOR.with(|validator| {
        let mut validator = validator.borrow_mut();
        let score = validator
            .score_group(group)
            .expect("embedded CredSweeper ONNX model runs");
        score >= validator.threshold
    })
}

#[cfg(test)]
pub(super) fn score_group_for_test(group: &[&MlInput]) -> (f32, f32) {
    VALIDATOR.with(|validator| {
        let mut validator = validator.borrow_mut();
        let score = validator
            .score_group(group)
            .expect("embedded CredSweeper ONNX model runs");
        (score, validator.threshold)
    })
}

#[cfg(test)]
pub(super) fn feature_width_matches_model_for_test() -> bool {
    VALIDATOR.with(|validator| {
        let validator = validator.borrow();
        validator.feature_width == validator.model.feature_width
            && validator.feature_width == validator.model.feature_attention.input_dim
            && validator.feature_width == validator.model.feature_attention.output_dim
    })
}

pub(super) fn ml_path(path: Option<&str>) -> String {
    path.unwrap_or_default().to_string()
}

pub(super) fn ml_file_type(path: Option<&str>) -> String {
    let Some(path) = path else {
        return String::new();
    };
    splitext(path).to_ascii_lowercase()
}

struct MlValidator {
    threshold: f32,
    char_dict: HashMap<char, usize>,
    common_features: Vec<FeatureSpec>,
    unique_features: Vec<FeatureSpec>,
    feature_width: usize,
    model: NativeModel,
}

#[derive(Deserialize)]
struct MlConfig {
    char_set: String,
    thresholds: HashMap<String, f32>,
    features: Vec<RawFeature>,
}

#[derive(Deserialize)]
struct RawFeature {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    kwargs: Value,
}

enum Attribute {
    Line,
    Value,
    Variable,
}

enum FeatureSpec {
    RuleSeverity,
    EntropyEvaluation,
    LengthOfAttribute {
        attribute: Attribute,
    },
    SearchInAttribute {
        regex: FancyRegex,
        attribute: Attribute,
    },
    WordInVariable {
        words: Vec<String>,
    },
    WordInValue {
        words: Vec<String>,
    },
    WordInPreamble {
        words: Vec<String>,
    },
    WordInTransition {
        words: Vec<String>,
    },
    WordInPostamble {
        words: Vec<String>,
    },
    WordInPath {
        words: Vec<String>,
    },
    MorphemeDense {
        morphemes: Vec<String>,
    },
    HasHtmlTag,
    IsSecretNumeric,
    FileExtension {
        extensions: Vec<String>,
    },
    RuleName {
        rule_names: Vec<String>,
    },
}

impl MlValidator {
    fn compile() -> Result<Self, String> {
        let config: MlConfig =
            serde_json::from_str(ML_CONFIG_JSON).map_err(|e| format!("ml config: {e}"))?;
        let threshold = config
            .thresholds
            .get("medium")
            .copied()
            .ok_or_else(|| "ml config missing medium threshold".to_string())?;

        let mut chars = config.char_set.chars().collect::<Vec<_>>();
        chars.sort_unstable();
        chars.dedup();
        if chars.contains(&ZERO_CHAR) || chars.contains(&FAKE_CHAR) {
            return Err("ml char_set contains reserved characters".to_string());
        }
        let mut char_dict = HashMap::with_capacity(chars.len() + 2);
        char_dict.insert(ZERO_CHAR, 0);
        char_dict.insert(FAKE_CHAR, 1);
        for (index, ch) in chars.into_iter().enumerate() {
            char_dict.insert(ch, index + 2);
        }
        let num_classes = char_dict.len();

        let mut common_features = Vec::new();
        let mut unique_features = Vec::new();
        for raw in config.features {
            let feature = FeatureSpec::from_raw(raw)?;
            if matches!(feature, FeatureSpec::RuleName { .. }) {
                unique_features.push(feature);
            } else {
                common_features.push(feature);
            }
        }
        let feature_width = common_features
            .iter()
            .chain(unique_features.iter())
            .map(FeatureSpec::width)
            .sum::<usize>();
        let model = NativeModel::from_onnx(ML_MODEL_ONNX, feature_width, num_classes)?;

        Ok(Self {
            threshold,
            char_dict,
            common_features,
            unique_features,
            feature_width,
            model,
        })
    }

    fn score_group(&mut self, group: &[&MlInput]) -> Result<f32, String> {
        let Some(default) = group.first().copied() else {
            return Ok(0.0);
        };
        let line_input = self.encode_line(&default.line, default.value_start);
        let variable = group
            .iter()
            .find_map(|candidate| {
                (!candidate.variable.is_empty()).then_some(candidate.variable.as_str())
            })
            .unwrap_or_default();
        let value = group
            .iter()
            .find_map(|candidate| (!candidate.value.is_empty()).then_some(candidate.value.as_str()))
            .unwrap_or_default();
        let variable_input = self.encode_value(variable);
        let value_input = self.encode_value(value);
        let feature_input = self.extract_features(group);
        Ok(self
            .model
            .predict(&line_input, &value_input, &variable_input, &feature_input))
    }

    fn encode_line(&self, text: &str, position: usize) -> Vec<Option<usize>> {
        let offset = text.chars().take_while(|ch| ch.is_whitespace()).count();
        let pos = byte_to_char_idx(text, position).saturating_sub(offset);
        let mut stripped = text.trim().to_string();
        if stripped.chars().count() > MAX_LEN {
            stripped = subtext(&stripped, pos, ML_HUNK);
        }
        self.encode(&stripped, MAX_LEN)
    }

    fn encode_value(&self, text: &str) -> Vec<Option<usize>> {
        let stripped = text.trim().chars().take(ML_HUNK).collect::<String>();
        self.encode(&stripped, ML_HUNK)
    }

    fn encode(&self, text: &str, limit: usize) -> Vec<Option<usize>> {
        let mut out = vec![None; limit];
        for (idx, ch) in text.chars().take(limit).enumerate() {
            let class = self.char_dict.get(&ch).copied().unwrap_or(1);
            out[idx] = Some(class);
        }
        out
    }

    fn extract_features(&self, group: &[&MlInput]) -> Vec<f32> {
        let default = group[0];
        let mut out = Vec::with_capacity(self.feature_width);
        for feature in &self.common_features {
            out.extend(feature.extract(default));
        }
        for feature in &self.unique_features {
            let mut merged = vec![0.0; feature.width()];
            for candidate in group {
                for (idx, value) in feature.extract(candidate).into_iter().enumerate() {
                    if value != 0.0 {
                        merged[idx] = 1.0;
                    }
                }
            }
            out.extend(merged);
        }
        out
    }
}

struct NativeModel {
    feature_attention: DenseNoBias,
    line_forward: LstmWeights,
    line_backward: LstmWeights,
    variable_forward: LstmWeights,
    variable_backward: LstmWeights,
    value_forward: LstmWeights,
    value_backward: LstmWeights,
    dense_a: Dense,
    dense_b: Dense,
    prediction: Dense,
    feature_width: usize,
}

struct DenseNoBias {
    kernel: Vec<f32>,
    input_dim: usize,
    output_dim: usize,
}

struct Dense {
    kernel: Vec<f32>,
    bias: Vec<f32>,
    input_dim: usize,
    output_dim: usize,
}

struct LstmWeights {
    input_kernel: Vec<f32>,
    recurrent_kernel: Vec<f32>,
    bias: Vec<f32>,
    input_dim: usize,
    units: usize,
}

impl NativeModel {
    fn from_onnx(bytes: &[u8], feature_width: usize, num_classes: usize) -> Result<Self, String> {
        let model = pb::ModelProto::decode(bytes).map_err(|e| format!("onnx protobuf: {e}"))?;
        let graph = model
            .graph
            .ok_or_else(|| "onnx graph missing".to_string())?;
        let feature_attention = DenseNoBias::new(
            initializer_f32(
                &graph,
                "StatefulPartitionedCall/model_1/feature_attention/MatMul/ReadVariableOp:0",
                &[feature_width, feature_width],
            )?,
            feature_width,
            feature_width,
        );
        let line_units = 128usize;
        let small_units = 64usize;
        let concat_width = 2 * line_units + 4 * small_units + feature_width;
        let dense_a = Dense::new(
            initializer_f32(
                &graph,
                "StatefulPartitionedCall/model_1/a_dense/MatMul/ReadVariableOp:0",
                &[concat_width, concat_width],
            )?,
            initializer_f32(
                &graph,
                "StatefulPartitionedCall/model_1/a_dense/BiasAdd/ReadVariableOp:0",
                &[concat_width],
            )?,
            concat_width,
            concat_width,
        );
        let dense_b = Dense::new(
            initializer_f32(
                &graph,
                "StatefulPartitionedCall/model_1/b_dense/MatMul/ReadVariableOp:0",
                &[concat_width, concat_width],
            )?,
            initializer_f32(
                &graph,
                "StatefulPartitionedCall/model_1/b_dense/BiasAdd/ReadVariableOp:0",
                &[concat_width],
            )?,
            concat_width,
            concat_width,
        );
        let prediction = Dense::new(
            initializer_f32(
                &graph,
                "StatefulPartitionedCall/model_1/prediction/MatMul/ReadVariableOp:0",
                &[concat_width, 1],
            )?,
            initializer_f32(
                &graph,
                "StatefulPartitionedCall/model_1/prediction/BiasAdd/ReadVariableOp:0",
                &[1],
            )?,
            concat_width,
            1,
        );

        Ok(Self {
            feature_attention,
            line_forward: load_lstm(&graph, "_5", "_6", "_7", num_classes, line_units)?,
            line_backward: load_lstm(&graph, "_8", "_9", "_10", num_classes, line_units)?,
            variable_forward: load_lstm(&graph, "_11", "_12", "_13", num_classes, small_units)?,
            variable_backward: load_lstm(&graph, "_14", "_15", "_16", num_classes, small_units)?,
            value_forward: load_lstm(&graph, "_17", "_18", "_19", num_classes, small_units)?,
            value_backward: load_lstm(&graph, "_20", "_21", "_22", num_classes, small_units)?,
            dense_a,
            dense_b,
            prediction,
            feature_width,
        })
    }

    fn predict(
        &self,
        line: &[Option<usize>],
        value: &[Option<usize>],
        variable: &[Option<usize>],
        features: &[f32],
    ) -> f32 {
        debug_assert_eq!(line.len(), MAX_LEN);
        debug_assert_eq!(value.len(), ML_HUNK);
        debug_assert_eq!(variable.len(), ML_HUNK);
        debug_assert_eq!(features.len(), self.feature_width);

        let mut attended_features = self.feature_attention.forward(features);
        softmax_in_place(&mut attended_features);
        for (feature, attention) in features.iter().zip(attended_features.iter_mut()) {
            *attention *= *feature;
        }

        let mut concatenated = Vec::with_capacity(
            self.line_forward.units
                + self.line_backward.units
                + self.variable_forward.units
                + self.variable_backward.units
                + self.value_forward.units
                + self.value_backward.units
                + self.feature_width,
        );
        concatenated.extend(self.line_forward.final_state(line, false));
        concatenated.extend(self.line_backward.final_state(line, true));
        concatenated.extend(self.variable_forward.final_state(variable, false));
        concatenated.extend(self.variable_backward.final_state(variable, true));
        concatenated.extend(self.value_forward.final_state(value, false));
        concatenated.extend(self.value_backward.final_state(value, true));
        concatenated.extend(attended_features);

        let mut dense_a = self.dense_a.forward(&concatenated);
        relu_in_place(&mut dense_a);
        let mut dense_b = self.dense_b.forward(&dense_a);
        relu_in_place(&mut dense_b);
        sigmoid(self.prediction.forward(&dense_b)[0])
    }
}

impl DenseNoBias {
    fn new(kernel: Vec<f32>, input_dim: usize, output_dim: usize) -> Self {
        Self {
            kernel,
            input_dim,
            output_dim,
        }
    }

    fn forward(&self, input: &[f32]) -> Vec<f32> {
        debug_assert_eq!(input.len(), self.input_dim);
        matmul_vec(input, &self.kernel, self.input_dim, self.output_dim)
    }
}

impl Dense {
    fn new(kernel: Vec<f32>, bias: Vec<f32>, input_dim: usize, output_dim: usize) -> Self {
        Self {
            kernel,
            bias,
            input_dim,
            output_dim,
        }
    }

    fn forward(&self, input: &[f32]) -> Vec<f32> {
        debug_assert_eq!(input.len(), self.input_dim);
        let mut out = matmul_vec(input, &self.kernel, self.input_dim, self.output_dim);
        for (value, bias) in out.iter_mut().zip(&self.bias) {
            *value += *bias;
        }
        out
    }
}

impl LstmWeights {
    fn final_state(&self, sequence: &[Option<usize>], reverse: bool) -> Vec<f32> {
        let gate_width = 4 * self.units;
        let mut hidden = vec![0.0; self.units];
        let mut cell = vec![0.0; self.units];
        let mut next_hidden = vec![0.0; self.units];
        let mut gates = vec![0.0; gate_width];

        for step in 0..sequence.len() {
            let index = if reverse {
                sequence.len() - 1 - step
            } else {
                step
            };
            gates.copy_from_slice(&self.bias);
            if let Some(class) = sequence[index].filter(|class| *class < self.input_dim) {
                let row = &self.input_kernel[class * gate_width..(class + 1) * gate_width];
                for (gate, weight) in gates.iter_mut().zip(row) {
                    *gate += *weight;
                }
            }
            for (unit, previous) in hidden.iter().copied().enumerate() {
                if previous == 0.0 {
                    continue;
                }
                let row = &self.recurrent_kernel[unit * gate_width..(unit + 1) * gate_width];
                for (gate, weight) in gates.iter_mut().zip(row) {
                    *gate += previous * *weight;
                }
            }
            for unit in 0..self.units {
                let input_gate = sigmoid(gates[unit]);
                let forget_gate = sigmoid(gates[self.units + unit]);
                let cell_gate = gates[2 * self.units + unit].tanh();
                let output_gate = sigmoid(gates[3 * self.units + unit]);
                cell[unit] = forget_gate * cell[unit] + input_gate * cell_gate;
                next_hidden[unit] = output_gate * cell[unit].tanh();
            }
            hidden.copy_from_slice(&next_hidden);
        }
        hidden
    }
}

fn load_lstm(
    graph: &pb::GraphProto,
    input_suffix: &str,
    bias_suffix: &str,
    recurrent_suffix: &str,
    input_dim: usize,
    units: usize,
) -> Result<LstmWeights, String> {
    let gate_width = 4 * units;
    Ok(LstmWeights {
        input_kernel: initializer_f32(
            graph,
            &format!("Func/StatefulPartitionedCall/input/{input_suffix}:0"),
            &[input_dim, gate_width],
        )?,
        bias: initializer_f32(
            graph,
            &format!("Func/StatefulPartitionedCall/input/{bias_suffix}:0"),
            &[gate_width],
        )?,
        recurrent_kernel: initializer_f32(
            graph,
            &format!("Func/StatefulPartitionedCall/input/{recurrent_suffix}:0"),
            &[units, gate_width],
        )?,
        input_dim,
        units,
    })
}

fn initializer_f32(
    graph: &pb::GraphProto,
    name: &str,
    expected_dims: &[usize],
) -> Result<Vec<f32>, String> {
    let tensor = graph
        .initializer
        .iter()
        .find(|tensor| tensor.name == name)
        .ok_or_else(|| format!("onnx initializer missing: {name}"))?;
    let dims = tensor
        .dims
        .iter()
        .map(|dim| *dim as usize)
        .collect::<Vec<_>>();
    if dims != expected_dims {
        return Err(format!(
            "onnx initializer {name} shape mismatch: {dims:?} != {expected_dims:?}"
        ));
    }
    if tensor.data_type != tensor_proto::DataType::Float as i32 {
        return Err(format!("onnx initializer {name} is not float32"));
    }
    let expected_len = expected_dims.iter().product::<usize>();
    let values = if tensor.raw_data.is_empty() {
        tensor.float_data.clone()
    } else {
        if tensor.raw_data.len() % 4 != 0 {
            return Err(format!(
                "onnx initializer {name} raw length is not float32 aligned"
            ));
        }
        tensor
            .raw_data
            .chunks_exact(4)
            .map(|chunk| f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<_>>()
    };
    if values.len() != expected_len {
        return Err(format!(
            "onnx initializer {name} value count mismatch: {} != {expected_len}",
            values.len()
        ));
    }
    Ok(values)
}

fn matmul_vec(input: &[f32], kernel: &[f32], input_dim: usize, output_dim: usize) -> Vec<f32> {
    let mut out = vec![0.0; output_dim];
    for row in 0..input_dim {
        let value = input[row];
        if value == 0.0 {
            continue;
        }
        let weights = &kernel[row * output_dim..(row + 1) * output_dim];
        for (out, weight) in out.iter_mut().zip(weights) {
            *out += value * *weight;
        }
    }
    out
}

fn softmax_in_place(values: &mut [f32]) {
    let max = values
        .iter()
        .copied()
        .fold(f32::NEG_INFINITY, |a, b| a.max(b));
    let mut sum = 0.0;
    for value in values.iter_mut() {
        *value = (*value - max).exp();
        sum += *value;
    }
    if sum != 0.0 {
        for value in values {
            *value /= sum;
        }
    }
}

fn relu_in_place(values: &mut [f32]) {
    for value in values {
        if *value < 0.0 {
            *value = 0.0;
        }
    }
}

fn sigmoid(value: f32) -> f32 {
    if value >= 0.0 {
        let z = (-value).exp();
        1.0 / (1.0 + z)
    } else {
        let z = value.exp();
        z / (1.0 + z)
    }
}

impl FeatureSpec {
    fn from_raw(raw: RawFeature) -> Result<Self, String> {
        match raw.kind.as_str() {
            "RuleSeverity" => Ok(Self::RuleSeverity),
            "EntropyEvaluation" => Ok(Self::EntropyEvaluation),
            "LengthOfAttribute" => Ok(Self::LengthOfAttribute {
                attribute: attribute_arg(&raw.kwargs)?,
            }),
            "SearchInAttribute" => Ok(Self::SearchInAttribute {
                regex: FancyRegex::new(&string_arg(&raw.kwargs, "pattern")?)
                    .map_err(|e| format!("ml search regex: {e}"))?,
                attribute: attribute_arg(&raw.kwargs)?,
            }),
            "WordInVariable" => Ok(Self::WordInVariable {
                words: words_arg(&raw.kwargs, "words")?,
            }),
            "WordInValue" => Ok(Self::WordInValue {
                words: words_arg(&raw.kwargs, "words")?,
            }),
            "WordInPreamble" => Ok(Self::WordInPreamble {
                words: words_arg(&raw.kwargs, "words")?,
            }),
            "WordInTransition" => Ok(Self::WordInTransition {
                words: words_arg(&raw.kwargs, "words")?,
            }),
            "WordInPostamble" => Ok(Self::WordInPostamble {
                words: words_arg(&raw.kwargs, "words")?,
            }),
            "WordInPath" => Ok(Self::WordInPath {
                words: words_arg(&raw.kwargs, "words")?,
            }),
            "MorphemeDense" => Ok(Self::MorphemeDense {
                morphemes: MORPHEME_CHECKLIST
                    .split_whitespace()
                    .map(str::to_string)
                    .collect(),
            }),
            "HasHtmlTag" => Ok(Self::HasHtmlTag),
            "IsSecretNumeric" => Ok(Self::IsSecretNumeric),
            "FileExtension" => Ok(Self::FileExtension {
                extensions: words_arg(&raw.kwargs, "extensions")?,
            }),
            "RuleName" => Ok(Self::RuleName {
                rule_names: words_arg(&raw.kwargs, "rule_names")?,
            }),
            other => Err(format!("unsupported CredSweeper ML feature {other}")),
        }
    }

    fn width(&self) -> usize {
        match self {
            Self::RuleSeverity
            | Self::LengthOfAttribute { .. }
            | Self::SearchInAttribute { .. }
            | Self::MorphemeDense { .. }
            | Self::HasHtmlTag
            | Self::IsSecretNumeric => 1,
            Self::EntropyEvaluation => 17,
            Self::WordInVariable { words }
            | Self::WordInValue { words }
            | Self::WordInPreamble { words }
            | Self::WordInTransition { words }
            | Self::WordInPostamble { words }
            | Self::WordInPath { words } => words.len(),
            Self::FileExtension { extensions } => extensions.len(),
            Self::RuleName { rule_names } => rule_names.len(),
        }
    }

    fn extract(&self, candidate: &MlInput) -> Vec<f32> {
        match self {
            Self::RuleSeverity => vec![match candidate.severity {
                RuleSeverity::Critical => 1.0,
                RuleSeverity::High => 0.75,
                RuleSeverity::Medium => 0.5,
                RuleSeverity::Low => 0.25,
                RuleSeverity::Info => 0.0,
            }],
            Self::EntropyEvaluation => entropy_evaluation(&candidate.value),
            Self::LengthOfAttribute { attribute } => {
                vec![length_of_attribute(
                    attribute.value(candidate),
                    attribute.hunk_plus(),
                )]
            }
            Self::SearchInAttribute { regex, attribute } => {
                let value = attribute.value(candidate);
                if !value.is_empty() && regex.is_match(value).unwrap_or(false) {
                    vec![1.0]
                } else {
                    vec![-1.0]
                }
            }
            Self::WordInVariable { words } => {
                word_in_string(words, &candidate.variable.to_lowercase())
            }
            Self::WordInValue { words } => word_in_string(words, &candidate.value.to_lowercase()),
            Self::WordInPreamble { words } => {
                word_in_string(words, &preamble(candidate).to_lowercase())
            }
            Self::WordInTransition { words } => {
                word_in_string(words, &transition(candidate).to_lowercase())
            }
            Self::WordInPostamble { words } => {
                word_in_string(words, &postamble(candidate).to_lowercase())
            }
            Self::WordInPath { words } => {
                word_in_string(words, &normalized_path_for_words(&candidate.path))
            }
            Self::MorphemeDense { morphemes } => {
                vec![morpheme_density(morphemes, &candidate.value)]
            }
            Self::HasHtmlTag => vec![has_html_tag(candidate)],
            Self::IsSecretNumeric => vec![if candidate.value.trim().parse::<f64>().is_ok() {
                1.0
            } else {
                -1.0
            }],
            Self::FileExtension { extensions } => {
                word_in_set(extensions, std::slice::from_ref(&candidate.file_type))
            }
            Self::RuleName { rule_names } => {
                word_in_set(rule_names, std::slice::from_ref(&candidate.rule_name))
            }
        }
    }
}

impl Attribute {
    fn value<'a>(&self, candidate: &'a MlInput) -> &'a str {
        match self {
            Self::Line => &candidate.line,
            Self::Value => &candidate.value,
            Self::Variable => &candidate.variable,
        }
    }

    fn hunk_plus(&self) -> usize {
        match self {
            Self::Line => 2 * ML_HUNK + 1,
            Self::Value | Self::Variable => ML_HUNK + 1,
        }
    }
}

fn attribute_arg(kwargs: &Value) -> Result<Attribute, String> {
    match string_arg(kwargs, "attribute")?.as_str() {
        "line" => Ok(Attribute::Line),
        "value" => Ok(Attribute::Value),
        "variable" => Ok(Attribute::Variable),
        other => Err(format!("unsupported ML attribute {other}")),
    }
}

fn string_arg(kwargs: &Value, key: &str) -> Result<String, String> {
    kwargs
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("ML feature missing string arg {key}"))
}

fn words_arg(kwargs: &Value, key: &str) -> Result<Vec<String>, String> {
    let mut words = kwargs
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("ML feature missing list arg {key}"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("ML feature {key} item is not a string"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let original_len = words.len();
    words.sort();
    words.dedup();
    if words.len() != original_len {
        return Err(format!("ML feature {key} has duplicate entries"));
    }
    Ok(words)
}

fn length_of_attribute(value: &str, hunk_plus: usize) -> f32 {
    let len = value.chars().count();
    if len == 0 {
        0.0
    } else if len < hunk_plus {
        len as f32 / hunk_plus as f32
    } else {
        1.0
    }
}

fn entropy_evaluation(value: &str) -> Vec<f32> {
    let chars = value.chars().take(4 * ML_HUNK).collect::<Vec<_>>();
    let size = chars.len();
    let mut result = vec![0.0; 17];
    let mut counts: HashMap<char, usize> = HashMap::new();
    for ch in &chars {
        *counts.entry(*ch).or_insert(0) += 1;
    }
    if size >= MIN_DATA_LEN {
        let hartley = (size as f64).log2();
        let probabilities = counts
            .values()
            .map(|count| *count as f64 / size as f64)
            .collect::<Vec<_>>();
        let renyi_05 = 2.0
            * probabilities
                .iter()
                .map(|probability| probability.powf(0.5))
                .sum::<f64>()
                .log2();
        let shannon = -probabilities
            .iter()
            .map(|probability| probability * probability.log2())
            .sum::<f64>();
        let renyi_2 = -probabilities
            .iter()
            .map(|probability| probability.powi(2))
            .sum::<f64>()
            .log2();
        result[0] = (renyi_05 / hartley) as f32;
        result[1] = (shannon / hartley) as f32;
        result[2] = (renyi_2 / hartley) as f32;
    }
    if size > 0 {
        for (idx, charset) in entropy_charsets().iter().enumerate() {
            if chars.iter().all(|ch| charset.contains(ch)) {
                result[idx + 3] = 1.0;
            }
        }
    }
    result
}

fn entropy_charsets() -> Vec<Vec<char>> {
    const DIGITS: &str = "0123456789";
    const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
    const PUNCT: &str = r##"!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"##;
    let base64_common = [UPPER, LOWER, DIGITS].concat();
    vec![
        [DIGITS, "ABCDEFabcdef"].concat(),
        [DIGITS, "ABCDEF-"].concat(),
        [DIGITS, "abcdef-"].concat(),
        [DIGITS, "ABCDEF"].concat(),
        [DIGITS, "abcdef"].concat(),
        [UPPER, "234567"].concat(),
        [DIGITS, LOWER].concat(),
        [DIGITS, UPPER, LOWER].concat(),
        [base64_common.as_str(), "-_"].concat(),
        [base64_common.as_str(), "-_="].concat(),
        [base64_common.as_str(), "+/"].concat(),
        [base64_common.as_str(), "+/="].concat(),
        [DIGITS, UPPER, LOWER, PUNCT].concat(),
        [DIGITS, UPPER, LOWER, PUNCT, " \t\n\r\x0b\x0c"].concat(),
    ]
    .into_iter()
    .map(|s| s.chars().collect())
    .collect()
}

fn word_in_string(words: &[String], data: &str) -> Vec<f32> {
    if data.is_empty() {
        return vec![0.0; words.len()];
    }
    words
        .iter()
        .map(|word| if data.contains(word) { 1.0 } else { 0.0 })
        .collect()
}

fn word_in_set(words: &[String], values: &[String]) -> Vec<f32> {
    words
        .iter()
        .map(|word| {
            if values.iter().any(|value| value == word) {
                1.0
            } else {
                0.0
            }
        })
        .collect()
}

fn preamble(candidate: &MlInput) -> String {
    let value_start = byte_to_char_idx(&candidate.line, candidate.value_start);
    let start_target = if candidate.variable_start >= 0 {
        byte_to_char_idx(&candidate.line, candidate.variable_start as usize)
    } else {
        value_start
    };
    let start = start_target.saturating_sub(ML_HUNK);
    slice_chars(&candidate.line, start, start_target)
        .trim()
        .to_string()
}

fn transition(candidate: &MlInput) -> String {
    if candidate.variable_end >= 0 && (candidate.variable_end as usize) < candidate.value_start {
        let start = byte_to_char_idx(&candidate.line, candidate.variable_end as usize);
        let end = byte_to_char_idx(&candidate.line, candidate.value_start);
        slice_chars(&candidate.line, start, end).trim().to_string()
    } else {
        String::new()
    }
}

fn postamble(candidate: &MlInput) -> String {
    let start = byte_to_char_idx(&candidate.line, candidate.value_end);
    let line_len = candidate.line.chars().count();
    let end = line_len.min(start + ML_HUNK);
    slice_chars(&candidate.line, start, end).trim().to_string()
}

fn normalized_path_for_words(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    let mut normalized = path.replace('\\', "/").to_lowercase();
    let absolute = normalized.starts_with('/')
        || normalized
            .as_bytes()
            .get(1..3)
            .is_some_and(|bytes| bytes[0] == b':' && bytes[1] == b'/');
    if !absolute {
        normalized = format!("./{}", normalized.trim_start_matches("./"));
    }
    strip_extension(&normalized)
}

fn morpheme_density(morphemes: &[String], value: &str) -> f32 {
    let value = value.to_lowercase();
    if value.is_empty() {
        return 0.0;
    }
    let mut morphemes_length = 0usize;
    for morpheme in morphemes {
        let mut search_from = 0usize;
        while let Some(pos) = value[search_from..].find(morpheme) {
            morphemes_length += morpheme.chars().count();
            search_from += pos + morpheme.len();
            if search_from >= value.len() {
                break;
            }
        }
    }
    (morphemes_length as f32 / value.chars().count() as f32).min(1.0)
}

fn has_html_tag(candidate: &MlInput) -> f32 {
    let subtext = subtext(
        &candidate.line,
        byte_to_char_idx(&candidate.line, candidate.value_start),
        CHUNK_SIZE,
    );
    let lower = subtext.to_lowercase();
    if !lower.contains('<') {
        return -1.0;
    }
    for word in [
        "< img", "<img", "< script", "<script", "< p", "<p", "< link", "<link", "< meta", "<meta",
        "< a", "<a",
    ] {
        if lower.contains(word) {
            return 1.0;
        }
    }
    if lower.contains("/>") || lower.contains("</") {
        1.0
    } else {
        -1.0
    }
}

fn subtext(text: &str, pos: usize, hunk_size: usize) -> String {
    let chars = text
        .trim_end_matches(is_python_whitespace)
        .chars()
        .collect::<Vec<_>>();
    let pos = pos.min(chars.len());
    let (mut left_quota, mut left_pos) = if hunk_size <= pos {
        (0usize, pos - hunk_size)
    } else {
        (hunk_size - pos, 0usize)
    };
    while left_pos < pos && is_python_whitespace(chars[left_pos]) {
        left_quota += 1;
        left_pos += 1;
    }
    let right_remain = chars.len().saturating_sub(pos);
    let (right_quota, mut right_pos) = if hunk_size <= right_remain {
        (0usize, pos + hunk_size + left_quota)
    } else {
        (hunk_size - right_remain, pos + hunk_size + left_quota)
    };
    right_pos = right_pos.min(chars.len());
    if left_pos > 0 {
        left_pos = left_pos.saturating_sub(right_quota);
    }
    chars[left_pos..right_pos]
        .iter()
        .collect::<String>()
        .trim_end_matches(is_python_whitespace)
        .to_string()
}

fn is_python_whitespace(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c')
}

fn byte_to_char_idx(text: &str, byte: usize) -> usize {
    text.char_indices()
        .take_while(|(idx, _)| *idx < byte)
        .count()
}

fn slice_chars(text: &str, start: usize, end: usize) -> String {
    text.chars()
        .skip(start)
        .take(end.saturating_sub(start))
        .collect()
}

fn splitext(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let file = normalized.rsplit('/').next().unwrap_or(normalized.as_str());
    let Some(dot) = file.rfind('.') else {
        return String::new();
    };
    if dot == 0 {
        return String::new();
    }
    file[dot..].to_string()
}

fn strip_extension(path: &str) -> String {
    let slash = path.rfind('/').map_or(0, |idx| idx + 1);
    let Some(dot_rel) = path[slash..].rfind('.') else {
        return path.to_string();
    };
    let dot = slash + dot_rel;
    if dot == slash {
        return path.to_string();
    }
    path[..dot].to_string()
}
