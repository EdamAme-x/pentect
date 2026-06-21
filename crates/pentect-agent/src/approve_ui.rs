use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io::{self, IsTerminal};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

pub struct ApprovalRequest {
    pub title: String,
    pub command: String,
    pub session: String,
    pub mode: String,
    pub header_note: String,
    pub approve_label: String,
    pub deny_label: String,
    pub footer_note: String,
    pub env: Vec<EnvReview>,
    pub warnings: Vec<String>,
}

pub struct EnvReview {
    pub name: String,
    pub action: EnvAction,
}

#[derive(Clone, Copy)]
pub enum EnvAction {
    Inject,
    Allow,
    Deny,
}

struct App<'a> {
    request: &'a ApprovalRequest,
    selected: ApprovalDecision,
    scroll: u16,
}

pub fn run(request: &ApprovalRequest) -> Result<ApprovalDecision, String> {
    if !io::stdout().is_terminal() {
        return Err("approval UI requires an interactive terminal".to_string());
    }

    enable_raw_mode().map_err(|e| format!("could not enter raw mode: {e}"))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)
        .map_err(|e| format!("could not enter alternate screen: {e}"))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal =
        Terminal::new(backend).map_err(|e| format!("could not create terminal: {e}"))?;

    let result = run_loop(&mut terminal, request);

    let restore_result = restore_terminal(&mut terminal);
    match (result, restore_result) {
        (Ok(decision), Ok(())) => Ok(decision),
        (Err(e), _) => Err(e),
        (Ok(_), Err(e)) => Err(e),
    }
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    request: &ApprovalRequest,
) -> Result<ApprovalDecision, String> {
    let mut app = App {
        request,
        selected: ApprovalDecision::Approve,
        scroll: 0,
    };
    loop {
        terminal
            .draw(|frame| draw(frame, &app))
            .map_err(|e| format!("could not draw approval UI: {e}"))?;
        let event = event::read().map_err(|e| format!("could not read key event: {e}"))?;
        if let Event::Key(key) = event {
            if key.kind == KeyEventKind::Release {
                continue;
            }
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('a') => return Ok(ApprovalDecision::Approve),
                KeyCode::Char('n') | KeyCode::Char('d') | KeyCode::Esc => {
                    return Ok(ApprovalDecision::Deny);
                }
                KeyCode::Enter => return Ok(app.selected),
                KeyCode::Tab | KeyCode::Left | KeyCode::Right => {
                    app.selected = match app.selected {
                        ApprovalDecision::Approve => ApprovalDecision::Deny,
                        ApprovalDecision::Deny => ApprovalDecision::Approve,
                    };
                }
                KeyCode::Up => app.scroll = app.scroll.saturating_sub(1),
                KeyCode::Down => app.scroll = app.scroll.saturating_add(1),
                KeyCode::Char('q') => return Ok(ApprovalDecision::Deny),
                _ => {}
            }
        }
    }
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<(), String> {
    disable_raw_mode().map_err(|e| format!("could not leave raw mode: {e}"))?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)
        .map_err(|e| format!("could not leave alternate screen: {e}"))?;
    terminal
        .show_cursor()
        .map_err(|e| format!("could not restore cursor: {e}"))
}

fn draw(frame: &mut Frame<'_>, app: &App<'_>) {
    let area = centered(frame.area(), 88, 24);
    frame.render_widget(Clear, area);
    let outer = Block::default()
        .title(Line::from(vec![
            Span::styled(
                " pentect ",
                Style::default().fg(Color::Black).bg(Color::Cyan),
            ),
            Span::styled(" approval ", Style::default().fg(Color::Cyan)),
        ]))
        .title_alignment(Alignment::Left)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));
    frame.render_widget(outer, area);

    let inner = area.inner(Margin {
        horizontal: 2,
        vertical: 1,
    });
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(5),
            Constraint::Length(3),
        ])
        .split(inner);

    draw_header(frame, chunks[0], app);
    draw_main(frame, chunks[1], app);
    draw_status(frame, chunks[2], app);
    draw_footer(frame, chunks[3], app);
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &App<'_>) {
    let request = app.request;
    let text = vec![
        Line::from(vec![
            Span::styled(&request.title, Style::default().fg(Color::White).bold()),
            Span::raw("  "),
            Span::styled(
                format!("scope: {}", request.session),
                Style::default().fg(Color::Gray),
            ),
            Span::raw("  "),
            Span::styled(
                format!("mode: {}", request.mode),
                Style::default().fg(Color::Gray),
            ),
        ]),
        Line::from(Span::styled(
            request.header_note.as_str(),
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(Paragraph::new(text), area);
}

fn draw_main(frame: &mut Frame<'_>, area: Rect, app: &App<'_>) {
    let title = if app.request.mode == "dashboard" {
        " status "
    } else {
        " command "
    };
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Blue));
    let text = Paragraph::new(app.request.command.as_str())
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((app.scroll, 0))
        .style(Style::default().fg(Color::White));
    frame.render_widget(text, area);
}

fn draw_status(frame: &mut Frame<'_>, area: Rect, app: &App<'_>) {
    let mut lines = Vec::new();
    if let Some(warning) = app.request.warnings.first() {
        lines.push(Line::from(vec![
            Span::styled("Warning: ", Style::default().fg(Color::Yellow).bold()),
            Span::styled(warning, Style::default().fg(Color::Yellow)),
        ]));
    } else {
        lines.push(Line::from(vec![
            Span::styled("Output: ", Style::default().fg(Color::Green).bold()),
            Span::raw("masked before the AI sees it."),
        ]));
    }
    lines.push(Line::from(vec![
        Span::styled("Secrets: ", Style::default().fg(Color::Cyan).bold()),
        Span::raw(secret_status(app.request)),
    ]));
    lines.push(Line::from(vec![
        Span::styled("Env: ", Style::default().fg(Color::Magenta).bold()),
        Span::raw(env_status(app.request)),
    ]));
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .title(" safety ")
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn secret_status(request: &ApprovalRequest) -> &'static str {
    if request.mode == "dashboard" {
        "local capability scope only."
    } else {
        "handles restore only inside local Pentect adapters."
    }
}

fn env_status(request: &ApprovalRequest) -> String {
    if request.env.is_empty() {
        return "no explicit env rule.".to_string();
    }
    let names = request
        .env
        .iter()
        .take(3)
        .map(|item| {
            let action = match item.action {
                EnvAction::Inject => "inject",
                EnvAction::Allow => "allow",
                EnvAction::Deny => "deny",
            };
            format!("{action} {}", item.name)
        })
        .collect::<Vec<_>>()
        .join(", ");
    if request.env.len() > 3 {
        format!("{names}, +{} more", request.env.len() - 3)
    } else {
        names
    }
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, app: &App<'_>) {
    let approve_style = selected_style(app.selected == ApprovalDecision::Approve, Color::Green);
    let deny_style = selected_style(app.selected == ApprovalDecision::Deny, Color::Red);
    let text = vec![
        Line::from(vec![
            Span::styled(format!("  {}  ", app.request.approve_label), approve_style),
            Span::raw("  "),
            Span::styled(format!("  {}  ", app.request.deny_label), deny_style),
            Span::raw("   "),
            Span::styled("Enter", Style::default().fg(Color::Cyan).bold()),
            Span::raw(" select   "),
            Span::styled("Tab", Style::default().fg(Color::Cyan).bold()),
            Span::raw(" switch   "),
            Span::styled("Y/N", Style::default().fg(Color::Cyan).bold()),
            Span::raw(" direct   "),
            Span::styled("Esc", Style::default().fg(Color::Cyan).bold()),
            Span::raw(" deny"),
        ]),
        Line::from(Span::styled(
            app.request.footer_note.as_str(),
            Style::default().fg(Color::DarkGray),
        )),
    ];
    frame.render_widget(Paragraph::new(text).alignment(Alignment::Center), area);
}

fn selected_style(selected: bool, color: Color) -> Style {
    let style = Style::default().fg(color).add_modifier(Modifier::BOLD);
    if selected {
        style.bg(Color::DarkGray)
    } else {
        style
    }
}

fn centered(area: Rect, max_width: u16, max_height: u16) -> Rect {
    let width = bounded_size(area.width, 50, max_width);
    let height = bounded_size(area.height, 16, max_height);
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect {
        x,
        y,
        width,
        height,
    }
}

fn bounded_size(available: u16, preferred_min: u16, max: u16) -> u16 {
    if available < preferred_min {
        available
    } else {
        available.min(max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, buffer::Buffer};

    #[test]
    fn approval_screen_explains_the_execution_contract() {
        let request = ApprovalRequest {
            title: "Approve command execution".to_string(),
            command: "Get-Content -Raw -LiteralPath .env".to_string(),
            session: "project".to_string(),
            mode: "shell".to_string(),
            header_note: "Run locally. Mask output before the AI sees it.".to_string(),
            approve_label: "APPROVE & RUN".to_string(),
            deny_label: "DENY".to_string(),
            footer_note: "Enter approve. Esc deny. Up/Down scroll.".to_string(),
            env: vec![EnvReview {
                name: "RUNPOD_API_KEY".to_string(),
                action: EnvAction::Inject,
            }],
            warnings: vec!["review direct env usage".to_string()],
        };
        let rendered = render_request(&request, 100, 34);

        assert!(rendered.contains("command"));
        assert!(rendered.contains("safety"));
        assert!(rendered.contains("Warning:"));
        assert!(rendered.contains("Secrets:"));
        assert!(rendered.contains("APPROVE & RUN"));
        assert!(!rendered.contains("resolves placeholders"));
        assert!(!rendered.contains("what happens"));
        assert!(!rendered.contains("environment policy"));
    }

    #[test]
    fn centered_area_never_exceeds_tiny_terminals() {
        let area = Rect::new(0, 0, 40, 12);
        let centered = centered(area, 100, 34);

        assert!(centered.width <= area.width);
        assert!(centered.height <= area.height);
    }

    fn render_request(request: &ApprovalRequest, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("test terminal");
        let app = App {
            request,
            selected: ApprovalDecision::Approve,
            scroll: 0,
        };
        terminal.draw(|frame| draw(frame, &app)).expect("draws UI");
        buffer_to_string(terminal.backend().buffer())
    }

    fn buffer_to_string(buffer: &Buffer) -> String {
        let mut rendered = String::new();
        for row in buffer.content().chunks(buffer.area.width as usize) {
            for cell in row {
                rendered.push_str(cell.symbol());
            }
            rendered.push('\n');
        }
        rendered
    }
}
