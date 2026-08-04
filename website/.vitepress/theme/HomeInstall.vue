<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';

type OperatingSystem = 'windows' | 'macos' | 'linux';
type Installer = { id: string; label: string; command: string; icon: string; tone: string };
type CommandToken = { text: string; kind: 'space' | 'command' | 'option' | 'string' | 'operator' | 'argument' };

const operatingSystems: Array<{
  id: OperatingSystem;
  label: string;
  icon: string;
  tone: string;
}> = [
  { id: 'windows', label: 'Windows', icon: '⊞', tone: 'windows' },
  { id: 'macos', label: 'macOS', icon: '⌘', tone: 'macos' },
  { id: 'linux', label: 'Linux', icon: '⌁', tone: 'linux' },
];

const npmInstaller = {
  id: 'npm',
  label: 'npm',
  command: 'npm install --global github:EdamAme-x/pentect',
  icon: 'npm',
  tone: 'npm',
};
const cargoInstaller = {
  id: 'cargo',
  label: 'Cargo',
  command: 'cargo install --git https://github.com/EdamAme-x/pentect --locked pentect-cli',
  icon: '⚙',
  tone: 'cargo',
};

const installers: Record<OperatingSystem, Installer[]> = {
  windows: [
    {
      id: 'powershell',
      label: 'PowerShell',
      command: 'irm https://pentect.dev/install | iex',
      icon: '>_',
      tone: 'powershell',
    },
    npmInstaller,
    cargoInstaller,
  ],
  macos: [
    {
      id: 'homebrew',
      label: 'Homebrew',
      command: 'brew install EdamAme-x/pentect/pentect',
      icon: 'B',
      tone: 'homebrew',
    },
    {
      id: 'shell',
      label: 'Shell',
      command: 'curl -fsSL https://pentect.dev/install.sh | sh',
      icon: '$_',
      tone: 'shell',
    },
    npmInstaller,
    {
      id: 'nix',
      label: 'Nix profile',
      command: 'nix profile install github:EdamAme-x/pentect',
      icon: '❄',
      tone: 'nix',
    },
    {
      id: 'nix-shell',
      label: 'Nix shell',
      command: 'nix shell github:EdamAme-x/pentect',
      icon: '❄',
      tone: 'nix',
    },
    cargoInstaller,
  ],
  linux: [
    {
      id: 'shell',
      label: 'Shell',
      command: 'curl -fsSL https://pentect.dev/install.sh | sh',
      icon: '$_',
      tone: 'shell',
    },
    {
      id: 'apt',
      label: 'APT',
      command: 'curl -fsSL https://pentect.dev/install-apt.sh | sudo sh',
      icon: 'A',
      tone: 'apt',
    },
    npmInstaller,
    {
      id: 'nix',
      label: 'Nix profile',
      command: 'nix profile install github:EdamAme-x/pentect',
      icon: '❄',
      tone: 'nix',
    },
    {
      id: 'nix-shell',
      label: 'Nix shell',
      command: 'nix shell github:EdamAme-x/pentect',
      icon: '❄',
      tone: 'nix',
    },
    cargoInstaller,
  ],
};

const selectedOs = ref<OperatingSystem>('windows');
const selectedMethod = ref('powershell');
const copyState = ref<'idle' | 'copied' | 'failed'>('idle');

const methods = computed(() => installers[selectedOs.value]);
const selectedInstaller = computed(
  () => methods.value.find((item) => item.id === selectedMethod.value) ?? methods.value[0],
);
const commandTokens = computed(() => tokenizeCommand(selectedInstaller.value.command));

function tokenizeCommand(command: string): CommandToken[] {
  const parts = command.match(/https?:\/\/[^\s|]+|github:[^\s|]+|--?[\w-]+|\||[^\s|]+|\s+/g) ?? [command];
  let expectsCommand = true;

  return parts.map((text) => {
    if (/^\s+$/.test(text)) return { text, kind: 'space' };
    if (text === '|') {
      expectsCommand = true;
      return { text, kind: 'operator' };
    }
    if (expectsCommand) {
      expectsCommand = false;
      return { text, kind: 'command' };
    }
    if (text.startsWith('-')) return { text, kind: 'option' };
    if (/^(?:https?:\/\/|github:)/.test(text)) return { text, kind: 'string' };
    return { text, kind: 'argument' };
  });
}

function chooseOs(os: OperatingSystem) {
  selectedOs.value = os;
  selectedMethod.value = installers[os][0].id;
  copyState.value = 'idle';
}

function chooseMethod(method: string) {
  selectedMethod.value = method;
  copyState.value = 'idle';
}

async function copyCommand() {
  try {
    await navigator.clipboard.writeText(selectedInstaller.value.command);
    copyState.value = 'copied';
  } catch {
    copyState.value = 'failed';
  }
}

onMounted(() => {
  const agent = navigator.userAgent.toLowerCase();
  chooseOs(agent.includes('mac') ? 'macos' : agent.includes('win') ? 'windows' : 'linux');
});
</script>

<template>
  <section class="home-install" aria-labelledby="install-heading">
    <div class="home-install__heading">
      <p id="install-heading">Install</p>
      <a href="/start/install/">All options <span aria-hidden="true">→</span></a>
    </div>

    <div class="home-install__controls">
      <div class="install-choice" role="group" aria-label="Operating system">
        <span class="install-choice__label">OS</span>
        <button
          v-for="os in operatingSystems"
          :key="os.id"
          type="button"
          :class="{ 'is-active': selectedOs === os.id }"
          :aria-pressed="selectedOs === os.id"
          @click="chooseOs(os.id)"
        >
          <i class="install-select__icon" :data-tone="os.tone" aria-hidden="true">{{ os.icon }}</i>
          {{ os.label }}
        </button>
      </div>

      <div class="install-choice" role="group" aria-label="Installation method">
        <span class="install-choice__label">Method</span>
        <button
          v-for="method in methods"
          :key="method.id"
          type="button"
          :class="{ 'is-active': selectedMethod === method.id }"
          :aria-pressed="selectedMethod === method.id"
          @click="chooseMethod(method.id)"
        >
          <i class="install-select__icon" :data-tone="method.tone" aria-hidden="true">{{ method.icon }}</i>
          {{ method.label }}
        </button>
      </div>
    </div>

    <div class="home-install__command">
      <code aria-live="polite">
        <span
          v-for="(token, index) in commandTokens"
          :key="`${index}-${token.text}`"
          :class="`shell-token shell-token--${token.kind}`"
        >{{ token.text }}</span>
      </code>
      <button
        type="button"
        class="home-install__copy"
        :class="{ 'is-copied': copyState === 'copied' }"
        :aria-label="copyState === 'copied' ? 'Copied' : 'Copy command'"
        :title="copyState === 'copied' ? 'Copied' : 'Copy command'"
        @click="copyCommand"
      >
        <svg v-if="copyState === 'copied'" aria-hidden="true" viewBox="0 0 24 24">
          <path d="m5 12 4 4L19 6" />
        </svg>
        <svg v-else aria-hidden="true" viewBox="0 0 24 24">
          <rect x="8" y="8" width="11" height="11" rx="2" />
          <path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3" />
        </svg>
      </button>
    </div>
    <p v-if="copyState === 'failed'" class="home-install__status" role="status">
      Select the command and copy it manually.
    </p>
  </section>
</template>
