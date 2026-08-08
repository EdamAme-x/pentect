import type {CSSProperties, ReactNode} from "react";
import {Audio} from "@remotion/media";
import {
  AbsoluteFill,
  Easing,
  Img,
  interpolate,
  staticFile,
  useCurrentFrame,
} from "remotion";

const COLORS = {
  bg: "#050505",
  panel: "#090909",
  line: "#292929",
  lineSoft: "#202020",
  text: "#f4f4f2",
  muted: "#a1a1a1",
  dim: "#6d6d6d",
  orange: "#f26a45",
  running: "#d7a84b",
  success: "#75c58b",
};

const SANS = '"Geist Variable", sans-serif';
const MONO = '"JetBrains Mono Variable", monospace';
const PROMPT = "Check the latest order with this live Stripe key:";
const SECRET = ["sk", "live", "51Qx7K9mN2vR4aBcD8eFgH6jØ"].join("_");
const HANDLE = "<<STRIPE_SECRET_KEY_a81f42c7d93>>";

const TYPE = {
  body: 22,
  secret: 22,
  code: 18,
} as const;

const LAYOUT = {
  outerX: 64,
  panelTop: 190,
  panelHeight: 620,
  leftWidth: 832,
  layerX: 912,
  layerWidth: 96,
  rightX: 1024,
  rightWidth: 832,
} as const;

const smooth = (frame: number, from: number, to: number) =>
  interpolate(frame, [from, to], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
    easing: Easing.bezier(0.16, 1, 0.3, 1),
  });

const mono: CSSProperties = {
  fontFamily: MONO,
  fontVariantLigatures: "none",
};

const surfaceShadow =
  "inset 0 1px 0 rgba(255,255,255,0.045), 0 18px 48px rgba(0,0,0,0.28)";

const Brand = ({frame}: {frame: number}) => {
  const enter = smooth(frame, 4, 20);
  return (
    <div
      style={{
        position: "absolute",
        left: LAYOUT.outerX,
        top: 76,
        display: "flex",
        alignItems: "center",
        gap: 16,
        opacity: enter,
        translate: `${interpolate(enter, [0, 1], [-18, 0])}px 0px`,
      }}
    >
      <Img src={staticFile("pentect-logo.png")} style={{width: 44, height: 44}} />
      <span
        style={{
          fontFamily: SANS,
          fontSize: 17,
          fontWeight: 650,
          letterSpacing: "0.16em",
        }}
      >
        PENTECT
      </span>
    </div>
  );
};

const AgentMark = () => (
  <svg width="28" height="28" viewBox="0 0 28 28" fill="none" aria-hidden="true">
    <rect x="2.75" y="4.25" width="22.5" height="19.5" rx="5" stroke={COLORS.text} strokeWidth="1.5" />
    <path d="M8.25 10.25 11.75 14l-3.5 3.75" stroke={COLORS.text} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M14.5 17.75h5.25" stroke={COLORS.text} strokeWidth="1.5" strokeLinecap="round" />
  </svg>
);

const UpstreamMark = () => (
  <svg width="27" height="27" viewBox="0 0 27 27" fill="none" aria-hidden="true">
    <rect x="3.5" y="4" width="20" height="7" rx="2.5" stroke={COLORS.text} strokeWidth="1.6" />
    <rect x="3.5" y="16" width="20" height="7" rx="2.5" stroke={COLORS.text} strokeWidth="1.6" />
    <circle cx="8" cy="7.5" r="1.2" fill={COLORS.text} />
    <circle cx="8" cy="19.5" r="1.2" fill={COLORS.text} />
  </svg>
);

const CurlCommand = ({credential}: {credential: ReactNode}) => (
  <div style={{fontSize: TYPE.code, lineHeight: 1.72, fontWeight: 480, ...mono}}>
    <div style={{display: "flex", alignItems: "center", whiteSpace: "nowrap"}}>
      <span style={{color: COLORS.dim}}>$&nbsp;</span>
      <span style={{color: COLORS.text}}>curl -sG &quot;https://api.stripe.com/v1/checkout/sessions&quot;&nbsp;</span>
      <span style={{color: COLORS.dim}}>{'\\'}</span>
    </div>
    <div style={{display: "flex", alignItems: "center", paddingLeft: 28, whiteSpace: "nowrap"}}>
      <span style={{color: COLORS.muted}}>-u&nbsp;</span>
      <span style={{color: COLORS.text}}>&quot;</span>
      {credential}
      <span style={{color: COLORS.text}}>:&quot;&nbsp;-d limit=1</span>
    </div>
  </div>
);

const FoldSwapText = ({frame, from, to}: {frame: number; from: string; to: string}) => (
  <span
    style={{
      position: "relative",
      display: "inline-block",
      width: `${Math.max(from.length, to.length)}ch`,
      height: "1.15em",
      verticalAlign: "-0.16em",
      perspective: 700,
    }}
  >
    <span style={{position: "absolute", inset: 0, whiteSpace: "nowrap"}}>
      {Array.from(from).map((char, index) => {
        const fold = smooth(frame, 600 + index * 0.45, 617 + index * 0.45);
        return (
          <span
            key={`from-${index}`}
            style={{
              display: "inline-block",
              color: COLORS.orange,
              opacity: 1 - fold,
              transform: `perspective(700px) rotateX(${-92 * fold}deg)`,
              transformOrigin: "50% 0%",
              backfaceVisibility: "hidden",
              filter: `brightness(${1 - fold * 0.28})`,
            }}
          >
            {char}
          </span>
        );
      })}
    </span>
    <span style={{position: "absolute", inset: 0, whiteSpace: "nowrap"}}>
      {Array.from(to).map((char, index) => {
        const unfold = smooth(frame, 616 + index * 0.45, 634 + index * 0.45);
        return (
          <span
            key={`to-${index}`}
            style={{
              display: "inline-block",
              color: COLORS.orange,
              opacity: unfold,
              transform: `perspective(700px) rotateX(${-92 * (1 - unfold)}deg)`,
              transformOrigin: "50% 0%",
              backfaceVisibility: "hidden",
              filter: `brightness(${0.72 + unfold * 0.28})`,
            }}
          >
            {char}
          </span>
        );
      })}
    </span>
  </span>
);

const BlurRevealText = ({
  frame,
  from,
  children,
}: {
  frame: number;
  from: number;
  children: string;
}) => (
  <span>
    {children.split(" ").map((word, index, words) => {
      const reveal = smooth(frame, from + index * 3.2, from + 15 + index * 3.2);
      return (
        <span
          key={`${word}-${index}`}
          style={{
            display: "inline-block",
            opacity: reveal,
            filter: `blur(${interpolate(reveal, [0, 1], [8, 0])}px)`,
            translate: `0px ${interpolate(reveal, [0, 1], [5, 0])}px`,
          }}
        >
          {word}
          {index < words.length - 1 ? "\u00a0" : ""}
        </span>
      );
    })}
  </span>
);

const BorderGlow = ({opacity}: {opacity: number}) => (
  <div
    style={{
      position: "absolute",
      inset: -1,
      borderRadius: "inherit",
      border: "1px solid rgba(255,118,84,0.9)",
      boxShadow:
        "inset 0 0 18px rgba(242,106,69,0.055), 0 0 12px rgba(242,106,69,0.18)",
      opacity: opacity * 0.72,
      pointerEvents: "none",
    }}
  />
);

const ClaudeToolUse = ({frame, successOpacity}: {frame: number; successOpacity: number}) => {
  const statusComplete = interpolate(frame, [655, 683], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const pulseProgress = interpolate(frame, [655, 705], [0, 1], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  });
  const completionGlow = Math.sin(pulseProgress * Math.PI);

  return (
  <div style={{fontSize: TYPE.code, lineHeight: 1.72, fontWeight: 480, ...mono}}>
    <div style={{display: "flex", alignItems: "baseline", gap: 11}}>
      <span
        style={{
          position: "relative",
          display: "inline-flex",
          width: 10,
          height: 10,
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        <span
          style={{
            position: "absolute",
            width: 9,
            height: 9,
            borderRadius: "50%",
            background: COLORS.success,
            opacity: completionGlow * 0.2,
            scale: 0.85 + pulseProgress * 1.55,
            filter: "blur(6px)",
          }}
        />
        <span
          style={{
            position: "absolute",
            width: 7,
            height: 7,
            borderRadius: "50%",
            background: COLORS.running,
            opacity: 1 - statusComplete,
          }}
        />
        <span
          style={{
            position: "absolute",
            width: 7,
            height: 7,
            borderRadius: "50%",
            background: COLORS.success,
            opacity: statusComplete,
          }}
        />
      </span>
      <span style={{color: COLORS.text}}>Bash</span>
    </div>
    <div style={{paddingLeft: 34, marginTop: 5, whiteSpace: "nowrap"}}>
      <span style={{color: COLORS.text}}>curl -sG &quot;https://api.stripe.com/v1/checkout/sessions&quot;&nbsp;</span>
      <span style={{color: COLORS.dim}}>{'\\'}</span>
    </div>
    <div style={{paddingLeft: 62, whiteSpace: "nowrap"}}>
      <span style={{color: COLORS.muted}}>-u&nbsp;</span>
      <span style={{color: COLORS.text}}>&quot;</span>
      <FoldSwapText frame={frame} from={HANDLE} to={SECRET} />
      <span style={{color: COLORS.text}}>:{'"'}&nbsp;-d limit=1</span>
    </div>
    <div
      style={{
        paddingLeft: 34,
        marginTop: 7,
        color: COLORS.muted,
        opacity: successOpacity,
      }}
    >
      ⎿ 1 checkout session returned
    </div>
  </div>
  );
};

const Panel = ({
  children,
  style,
  glow = 0,
}: {
  children: ReactNode;
  style?: CSSProperties;
  glow?: number;
}) => (
  <div
    style={{
      position: "absolute",
      border: `1px solid ${COLORS.line}`,
      background: COLORS.panel,
      boxShadow: surfaceShadow,
      overflow: "hidden",
      ...style,
    }}
  >
    {children}
    <BorderGlow opacity={glow} />
  </div>
);

const ClaudePanel = ({frame}: {frame: number}) => {
  const enter = smooth(frame, 10, 32);
  const typedChars = Math.floor(interpolate(frame, [45, 145], [0, `${PROMPT}\n${SECRET}`.length], {
    extrapolateLeft: "clamp",
    extrapolateRight: "clamp",
  }));
  const typed = `${PROMPT}\n${SECRET}`.slice(0, typedChars);
  const [typedPrompt = "", typedSecret = ""] = typed.split("\n");
  const sent = smooth(frame, 160, 175);
  const commandIn = smooth(frame, 560, 585);
  const successIn = smooth(frame, 655, 675);
  const restoreGlow = smooth(frame, 545, 562) * (1 - smooth(frame, 660, 680));

  return (
    <Panel
      glow={restoreGlow}
      style={{
        left: LAYOUT.outerX,
        top: LAYOUT.panelTop,
        width: LAYOUT.leftWidth,
        height: LAYOUT.panelHeight,
        borderRadius: 14,
        opacity: enter,
        translate: `${interpolate(enter, [0, 1], [-14, 0])}px 0px`,
        scale: interpolate(enter, [0, 1], [0.992, 1]),
        filter: `blur(${interpolate(enter, [0, 1], [7, 0])}px)`,
      }}
    >
      <div
        style={{
          height: 72,
          borderBottom: `1px solid ${COLORS.lineSoft}`,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0 28px",
        }}
      >
        <div style={{display: "flex", alignItems: "center", gap: 15}}>
          <AgentMark />
          <span style={{fontSize: 18, fontWeight: 650, letterSpacing: "-0.01em"}}>AI agent</span>
        </div>
        <div style={{fontFamily: MONO, color: COLORS.dim, fontSize: 17}}>~/ec</div>
      </div>

      <div
        style={{
          position: "relative",
          height: "calc(100% - 72px)",
          padding: "15px 46px",
          ...mono,
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "flex-start",
            gap: 18,
            opacity: sent,
            translate: `0px ${interpolate(sent, [0, 1], [18, 0])}px`,
          }}
        >
          <div style={{fontSize: 24, color: COLORS.muted, lineHeight: 1.55, fontWeight: 520, ...mono}}>❯</div>
          <div
            style={{
              flex: 1,
              fontSize: TYPE.body,
              lineHeight: 1.65,
              fontWeight: 470,
            }}
          >
            {PROMPT}
            <div style={{color: COLORS.orange, marginTop: 4, fontSize: TYPE.secret, fontWeight: 520}}>{SECRET}</div>
          </div>
        </div>

        <div
          style={{
            position: "absolute",
            top: 173,
            left: 46,
            right: 46,
            opacity: commandIn,
            translate: `0px ${interpolate(commandIn, [0, 1], [22, 0])}px`,
          }}
        >
          <div style={{fontSize: TYPE.body, lineHeight: 1.65, fontWeight: 470}}>I’ll check the latest order.</div>
        </div>

        <div
          style={{
            position: "absolute",
            top: 240,
            left: 46,
            right: 46,
            opacity: commandIn,
            translate: `0px ${interpolate(commandIn, [0, 1], [9, 0])}px`,
          }}
        >
          <ClaudeToolUse frame={frame} successOpacity={successIn} />
        </div>
      </div>

      <div
        style={{
          position: "absolute",
          left: 30,
          right: 30,
          bottom: 22,
          height: 138,
          borderTop: `1px solid ${COLORS.line}`,
          padding: "22px 25px",
          opacity: 1 - smooth(frame, 159, 174),
        }}
      >
        <div style={{display: "flex", alignItems: "flex-start", gap: 14, fontSize: TYPE.body, lineHeight: 1.6, fontWeight: 470, ...mono}}>
          <span style={{color: COLORS.muted, fontSize: 23, lineHeight: 1.42}}>❯</span>
          <div style={{whiteSpace: "pre-wrap"}}>
            <div>
              {typedPrompt}
              {!typed.includes("\n") ? (
                <span style={{opacity: frame % 18 < 9 ? 1 : 0, color: COLORS.orange}}>▋</span>
              ) : null}
            </div>
            {typed.includes("\n") ? (
              <div style={{color: COLORS.orange, fontSize: TYPE.secret}}>
                {typedSecret}
                <span style={{opacity: frame % 18 < 9 ? 1 : 0}}>▋</span>
              </div>
            ) : null}
          </div>
        </div>
        <div style={{position: "absolute", right: 22, bottom: 17, color: COLORS.dim, fontSize: 16}}>↵ send</div>
      </div>
    </Panel>
  );
};

const ProviderPanel = ({frame}: {frame: number}) => {
  const enter = smooth(frame, 18, 42);
  const requestIn = smooth(frame, 280, 310);
  const thinkingIn = smooth(frame, 330, 355);
  const responseIn = smooth(frame, 430, 458);
  const toolIn = smooth(frame, 486, 514);
  const requestGlow = smooth(frame, 245, 265) * (1 - smooth(frame, 320, 340));
  const dots = ".".repeat(1 + (Math.floor(frame / 12) % 3));

  return (
    <Panel
      glow={requestGlow}
      style={{
        left: LAYOUT.rightX,
        top: LAYOUT.panelTop,
        width: LAYOUT.rightWidth,
        height: LAYOUT.panelHeight,
        borderRadius: 14,
        opacity: enter,
        translate: `${interpolate(enter, [0, 1], [14, 0])}px 0px`,
        scale: interpolate(enter, [0, 1], [0.992, 1]),
        filter: `blur(${interpolate(enter, [0, 1], [7, 0])}px)`,
      }}
    >
      <div
        style={{
          height: 72,
          borderBottom: `1px solid ${COLORS.lineSoft}`,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0 28px",
        }}
      >
        <div style={{display: "flex", alignItems: "center", gap: 13}}>
          <UpstreamMark />
          <span style={{fontSize: 18, fontWeight: 650, letterSpacing: "-0.01em"}}>Upstream</span>
        </div>
        <span style={{fontSize: 14, color: COLORS.dim, ...mono}}>what the model sees</span>
      </div>

      <div style={{position: "relative", height: "calc(100% - 72px)", padding: "15px 46px", ...mono}}>
        <div
          style={{
            display: "flex",
            alignItems: "flex-start",
            gap: 18,
            opacity: requestIn,
            translate: `0px ${interpolate(requestIn, [0, 1], [18, 0])}px`,
          }}
        >
          <div style={{fontSize: 24, color: COLORS.muted, lineHeight: 1.55, fontWeight: 520}}>❯</div>
          <div style={{flex: 1}}>
            <div style={{fontSize: TYPE.body, lineHeight: 1.65, fontWeight: 470}}>{PROMPT}</div>
            <div style={{fontSize: TYPE.secret, color: COLORS.orange, marginTop: 4, fontWeight: 520}}>{HANDLE}</div>
          </div>
        </div>

        <div
          style={{
            position: "absolute",
            top: 173,
            left: 46,
            right: 46,
            opacity: thinkingIn * (1 - smooth(frame, 415, 430)),
            color: COLORS.muted,
            fontSize: 17,
          }}
        >
          Thinking{dots}
        </div>

        <div
          style={{
            position: "absolute",
            top: 173,
            left: 46,
            right: 46,
            opacity: responseIn,
            translate: `0px ${interpolate(responseIn, [0, 1], [20, 0])}px`,
          }}
        >
          <div style={{fontSize: TYPE.body, lineHeight: 1.65, fontWeight: 470}}>
            <BlurRevealText frame={frame} from={430}>I’ll check the latest order.</BlurRevealText>
          </div>
        </div>

        <div
          style={{
            position: "absolute",
            top: 240,
            left: 46,
            right: 46,
            paddingTop: 20,
            borderTop: `1px solid ${COLORS.line}`,
            opacity: toolIn,
            clipPath: `inset(0 ${interpolate(toolIn, [0, 1], [100, 0])}% 0 0)`,
            translate: `0px ${interpolate(toolIn, [0, 1], [9, 0])}px`,
          }}
        >
          <CurlCommand credential={<span style={{color: COLORS.orange}}>{HANDLE}</span>} />
        </div>
      </div>
    </Panel>
  );
};

const SignalBeam = ({
  frame,
  start,
  top,
  direction,
}: {
  frame: number;
  start: number;
  top: number;
  direction: "left" | "right";
}) => {
  const beamWidth = LAYOUT.layerWidth + 32;
  const draw = smooth(frame, start, start + 24);
  const coreRelease = smooth(frame, start + 31, start + 52);
  const bloomRelease = smooth(frame, start + 36, start + 62);
  const coreActive = draw * (1 - coreRelease);
  const bloomActive = draw * (1 - bloomRelease);
  const targetX = direction === "right" ? beamWidth : 0;
  const origin = direction === "right" ? "left center" : "right center";
  const targetPulse = smooth(frame, start + 20, start + 26) * (1 - smooth(frame, start + 38, start + 60));
  const beamGradient =
    direction === "right"
      ? "linear-gradient(90deg, rgba(242,106,69,0.28), #f26a45 72%, #ffe9df 100%)"
      : "linear-gradient(90deg, #ffe9df 0%, #f26a45 28%, rgba(242,106,69,0.28))";

  return (
    <div
      style={{
        position: "absolute",
        left: 0,
        right: 0,
        top,
        height: 1,
      }}
    >
      <div
        style={{
          position: "absolute",
          left: 0,
          right: 0,
          top: 0,
          height: 1,
          background: "rgba(255,255,255,0.13)",
        }}
      />
      <div
        style={{
          position: "absolute",
          left: 0,
          right: 0,
          top: -2,
          height: 5,
          opacity: bloomActive * 0.34,
          background: COLORS.orange,
          filter: "blur(4px)",
          scale: `${draw} 1`,
          transformOrigin: origin,
        }}
      />
      <div
        style={{
          position: "absolute",
          left: 0,
          right: 0,
          top: -1,
          height: 2,
          opacity: coreActive * 0.88,
          background: beamGradient,
          boxShadow: "0 0 5px rgba(242,106,69,0.42)",
          scale: `${draw} 1`,
          transformOrigin: origin,
        }}
      />
      <div
        style={{
          position: "absolute",
          left: targetX - 6,
          top: -6,
          width: 13,
          height: 13,
          opacity: targetPulse * 0.45,
          borderRadius: "50%",
          background:
            "radial-gradient(circle, rgba(255,236,226,0.72) 0%, rgba(242,106,69,0.28) 34%, rgba(242,106,69,0) 74%)",
          filter: "blur(2px)",
        }}
      />
    </div>
  );
};

const PentectLayer = ({frame}: {frame: number}) => {
  const enter = smooth(frame, 18, 40);
  return (
    <div
      style={{
        position: "absolute",
        left: LAYOUT.layerX - 16,
        top: LAYOUT.panelTop,
        width: LAYOUT.layerWidth + 32,
        height: LAYOUT.panelHeight,
        opacity: enter,
      }}
    >
      <Img
        src={staticFile("pentect-logo.png")}
        style={{
          position: "absolute",
          left: "50%",
          top: 22,
          width: 28,
          height: 28,
          translate: "-50% 0",
        }}
      />
      <SignalBeam frame={frame} start={245} top={170} direction="right" />
      <SignalBeam frame={frame} start={545} top={420} direction="left" />
    </div>
  );
};

const Finale = ({frame}: {frame: number}) => {
  const cover = smooth(frame, 760, 780);
  const first = smooth(frame, 772, 796);
  const second = smooth(frame, 788, 816);
  return (
    <AbsoluteFill
      style={{
        display: frame < 760 ? "none" : "flex",
        background: COLORS.bg,
        opacity: cover,
        padding: "0 150px",
        justifyContent: "center",
      }}
    >
      <div
        style={{
          position: "absolute",
          left: 150,
          top: 120,
          display: "flex",
          alignItems: "center",
          gap: 14,
        }}
      >
        <Img src={staticFile("pentect-logo.png")} style={{width: 48, height: 48}} />
        <span style={{fontSize: 18, fontWeight: 750, letterSpacing: "0.18em"}}>PENTECT</span>
      </div>
      <div
        style={{
          fontFamily: SANS,
          fontSize: 104,
          fontWeight: 720,
          letterSpacing: "-0.055em",
          lineHeight: 1.06,
        }}
      >
        <div
          style={{
            opacity: first,
            translate: `${interpolate(first, [0, 1], [-34, 0])}px 0px`,
          }}
        >
          AI used the secret.
        </div>
        <div
          style={{
            color: COLORS.orange,
            opacity: second,
            translate: `${interpolate(second, [0, 1], [-34, 0])}px 0px`,
          }}
        >
          AI never saw it.
        </div>
      </div>
      <div style={{position: "absolute", right: 150, bottom: 86, color: COLORS.muted, fontSize: 22}}>pentect.dev</div>
    </AbsoluteFill>
  );
};

export const PentectDemo: React.FC = () => {
  const sourceFrame = useCurrentFrame();
  const frame = sourceFrame * 1.25;
  const canvasExit = 1 - smooth(frame, 758, 778);

  return (
    <AbsoluteFill style={{background: COLORS.bg, color: COLORS.text, fontFamily: SANS}}>
      <Audio
        src={staticFile("audio/close-up-bed.mp3")}
        trimBefore={120}
        volume={(audioFrame) =>
          interpolate(audioFrame, [0, 45, 600, 679], [0, 0.2, 0.2, 0], {
            extrapolateLeft: "clamp",
            extrapolateRight: "clamp",
          })
        }
      />
      <div
        style={{
          position: "absolute",
          inset: 0,
          opacity: canvasExit,
          background: COLORS.bg,
        }}
      />
      <div style={{opacity: canvasExit}}>
        <Brand frame={frame} />
        <ClaudePanel frame={frame} />
        <ProviderPanel frame={frame} />
        <PentectLayer frame={frame} />
      </div>
      <Finale frame={frame} />
    </AbsoluteFill>
  );
};
