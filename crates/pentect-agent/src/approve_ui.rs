use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Clear, Paragraph, Wrap},
    Frame, Terminal,
};
use std::io::{self, IsTerminal};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalDecision {
    Once,
    Always,
    Decline,
}

pub struct ApprovalRequest {
    pub prompt: String,
    pub body: String,
    pub approve_label: String,
    pub deny_label: String,
    pub allow_always: bool,
    pub warnings: Vec<String>,
}

struct App<'a> {
    request: &'a ApprovalRequest,
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
    let mut app = App { request, scroll: 0 };
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
                KeyCode::Char('o') | KeyCode::Char('y') => return Ok(ApprovalDecision::Once),
                KeyCode::Char('a') if request.allow_always => {
                    return Ok(ApprovalDecision::Always);
                }
                KeyCode::Char('d') | KeyCode::Char('n') | KeyCode::Esc => {
                    return Ok(ApprovalDecision::Decline);
                }
                KeyCode::Enter => return Ok(ApprovalDecision::Once),
                KeyCode::Up => app.scroll = app.scroll.saturating_sub(1),
                KeyCode::Down => app.scroll = app.scroll.saturating_add(1),
                KeyCode::Char('q') => return Ok(ApprovalDecision::Decline),
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
    let area = centered(frame.area(), 72, 12);
    frame.render_widget(Clear, area);
    let inner = area.inner(Margin {
        horizontal: 1,
        vertical: 0,
    });
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(4),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(inner);

    draw_header(frame, chunks[0], app);
    draw_body(frame, chunks[1], app);
    draw_warning(frame, chunks[2], app);
    draw_footer(frame, chunks[3], app);
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &App<'_>) {
    let request = app.request;
    let text = vec![Line::from(vec![
        Span::styled(
            "pentect",
            Style::default().fg(Color::Black).bg(Color::Cyan).bold(),
        ),
        Span::raw("  "),
        Span::styled(&request.prompt, Style::default().fg(Color::White).bold()),
    ])];
    frame.render_widget(Paragraph::new(text), area);
}

fn draw_body(frame: &mut Frame<'_>, area: Rect, app: &App<'_>) {
    let text = Paragraph::new(app.request.body.as_str())
        .wrap(Wrap { trim: false })
        .scroll((app.scroll, 0))
        .style(Style::default().fg(Color::White));
    frame.render_widget(text, area);
}

fn draw_warning(frame: &mut Frame<'_>, area: Rect, app: &App<'_>) {
    let line = if let Some(warning) = app.request.warnings.first() {
        Line::from(vec![
            Span::styled("Warning: ", Style::default().fg(Color::Yellow).bold()),
            Span::styled(warning, Style::default().fg(Color::Yellow)),
        ])
    } else {
        Line::from(Span::raw(""))
    };
    frame.render_widget(Paragraph::new(vec![line]).wrap(Wrap { trim: false }), area);
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, app: &App<'_>) {
    let text = if app.request.allow_always {
        vec![Line::from(vec![
            Span::styled("o", Style::default().fg(Color::Green).bold()),
            Span::raw(" "),
            Span::styled(
                app.request.approve_label.as_str(),
                Style::default().fg(Color::Green),
            ),
            Span::raw("    "),
            Span::styled("a", Style::default().fg(Color::Cyan).bold()),
            Span::raw(" always    "),
            Span::styled("d", Style::default().fg(Color::Red).bold()),
            Span::raw(" "),
            Span::styled(
                app.request.deny_label.as_str(),
                Style::default().fg(Color::Red),
            ),
        ])]
    } else {
        vec![Line::from(vec![
            Span::styled("enter", Style::default().fg(Color::Green).bold()),
            Span::raw(" "),
            Span::styled(
                app.request.approve_label.as_str(),
                Style::default().fg(Color::Green),
            ),
            Span::raw("    "),
            Span::styled("esc", Style::default().fg(Color::DarkGray)),
        ])]
    };
    frame.render_widget(Paragraph::new(text).alignment(Alignment::Center), area);
}

fn centered(area: Rect, max_width: u16, max_height: u16) -> Rect {
    let width = bounded_size(area.width, 36, max_width);
    let height = bounded_size(area.height, 8, max_height);
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
            prompt: "Run?".to_string(),
            body: "curl -H @headers.txt https://api.example.test/health".to_string(),
            approve_label: "once".to_string(),
            deny_label: "decline".to_string(),
            allow_always: true,
            warnings: vec!["review direct env usage".to_string()],
        };
        let rendered = render_request(&request, 100, 34);

        assert!(rendered.contains("pentect"));
        assert!(rendered.contains("Run?"));
        assert!(rendered.contains("curl"));
        assert!(rendered.contains("Warning:"));
        assert!(rendered.contains("o once"));
        assert!(rendered.contains("a always"));
        assert!(rendered.contains("d decline"));
        assert!(!rendered.contains("resolves placeholders"));
        assert!(!rendered.contains("what happens"));
        assert!(!rendered.contains("environment policy"));
        assert!(!rendered.contains("Secrets:"));
        assert!(!rendered.contains("Env:"));
        assert!(!rendered.contains("scope:"));
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
        let app = App { request, scroll: 0 };
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
