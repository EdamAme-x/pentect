import * as vscode from 'vscode';
import { PentectBackend } from './backend';
import { PentectChatModelProvider } from './provider';

export function activate(context: vscode.ExtensionContext): void {
  const backend = new PentectBackend(readSettings);
  const provider = new PentectChatModelProvider(backend);

  context.subscriptions.push(
    backend,
    provider,
    vscode.lm.registerLanguageModelChatProvider('pentect', provider),
    vscode.commands.registerCommand('pentect.manageProvider', async () => {
      await vscode.commands.executeCommand('workbench.action.openSettings', '@ext:pentect.pentect-vscode');
    }),
    vscode.commands.registerCommand('pentect.restartProvider', () => {
      backend.restart();
      void vscode.window.showInformationMessage('Pentect language model provider restarted.');
    }),
    vscode.workspace.onDidChangeConfiguration(event => {
      if (event.affectsConfiguration('pentect.executablePath') || event.affectsConfiguration('pentect.vscode')) {
        backend.restart();
        provider.refresh();
      }
    }),
  );
}

export function deactivate(): void {}

function readSettings() {
  const config = vscode.workspace.getConfiguration('pentect');
  const upstream = config.get<string>('vscode.upstream', '').trim();
  return {
    executable: config.get<string>('executablePath', 'pentect').trim() || 'pentect',
    model: config.get<string>('vscode.model', 'gpt-5').trim() || 'gpt-5',
    ...(upstream ? { upstream } : {}),
  };
}
