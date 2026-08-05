<script setup lang="ts">
import {
  siApple,
  siDebian,
  siGnubash,
  siHomebrew,
  siLinux,
  siNixos,
  siNpm,
  siRust,
} from 'simple-icons';
import { computed, onMounted, ref } from 'vue';

type OperatingSystem = 'windows' | 'macos' | 'linux';
type InstallerVariant = { id: string; label: string; command: string };
type Installer = {
  id: string;
  label: string;
  command: string;
  icon: string;
  tone: string;
  variants?: InstallerVariant[];
};
type CommandToken = {
  text: string;
  kind: 'space' | 'comment' | 'command' | 'option' | 'string' | 'operator' | 'argument';
};

const operatingSystems: Array<{
  id: OperatingSystem;
  label: string;
  icon: string;
  tone: string;
}> = [
  { id: 'windows', label: 'Windows', icon: 'windows', tone: 'windows' },
  { id: 'macos', label: 'macOS', icon: 'apple', tone: 'macos' },
  { id: 'linux', label: 'Linux', icon: 'linux', tone: 'linux' },
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
  icon: 'rust',
  tone: 'cargo',
};
const nixInstaller: Installer = {
  id: 'nix',
  label: 'Nix',
  command: '# Temporary environment; nothing is installed permanently\nnix shell github:EdamAme-x/pentect',
  icon: 'nixos',
  tone: 'nix',
  variants: [
    {
      id: 'shell',
      label: 'Shell',
      command: '# Temporary environment; nothing is installed permanently\nnix shell github:EdamAme-x/pentect',
    },
    {
      id: 'profile',
      label: 'Profile',
      command: '# Install once\nnix profile install github:EdamAme-x/pentect\n\n# Update later\nnix profile upgrade pentect',
    },
    {
      id: 'nixos',
      label: 'NixOS',
      command: '# flake.nix\ninputs.pentect.url = "github:EdamAme-x/pentect";\n\n# In a module where `inputs` and `pkgs` are available\nenvironment.systemPackages = [\n  inputs.pentect.packages.${pkgs.system}.default\n];',
    },
  ],
};

const installers: Record<OperatingSystem, Installer[]> = {
  windows: [
    {
      id: 'powershell',
      label: 'PowerShell',
      command: 'irm https://pentect.dev/install | iex',
      icon: 'powershell',
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
      icon: 'homebrew',
      tone: 'homebrew',
    },
    {
      id: 'shell',
      label: 'Shell',
      command: 'curl -fsSL https://pentect.dev/install.sh | sh',
      icon: 'gnubash',
      tone: 'shell',
    },
    npmInstaller,
    nixInstaller,
    cargoInstaller,
  ],
  linux: [
    {
      id: 'shell',
      label: 'Shell',
      command: 'curl -fsSL https://pentect.dev/install.sh | sh',
      icon: 'gnubash',
      tone: 'shell',
    },
    {
      id: 'apt',
      label: 'APT repository',
      command: '# First install: add the Pentect APT repository and install\ncurl -fsSL https://pentect.dev/install-apt.sh | sudo sh\n\n# Update later through APT\nsudo apt update && sudo apt install --only-upgrade pentect',
      icon: 'debian',
      tone: 'apt',
    },
    npmInstaller,
    nixInstaller,
    cargoInstaller,
  ],
};

const selectedOs = ref<OperatingSystem>('windows');
const selectedMethod = ref('powershell');
const selectedVariant = ref<string | null>(null);
const copyState = ref<'idle' | 'copied' | 'failed'>('idle');
const iconSet: Record<string, string> = {
  windows: 'M0 0h11.377v11.372H0Zm12.623 0H24v11.372H12.623ZM0 12.623h11.377V24H0Zm12.623 0H24V24H12.623',
  apple: siApple.path,
  linux: siLinux.path,
  powershell: 'M23.181 2.974c.568 0 .923.463.792 1.035l-3.659 15.982c-.13.572-.697 1.035-1.265 1.035H.819c-.568 0-.923-.463-.792-1.035L3.686 4.009c.13-.572.697-1.035 1.265-1.035zm-8.375 9.346c.251-.394.227-.905-.09-1.243L9.122 5.125c-.38-.404-1.037-.407-1.466-.003c-.429.402-.468 1.056-.088 1.46l4.662 4.96v.11l-7.42 5.374c-.45.327-.533.977-.187 1.453s.991.597 1.44.27l8.229-5.91c.28-.196.438-.365.514-.52zm-2.796 4.399a.93.93 0 0 0-.934.923c0 .51.418.923.934.923h4.433a.93.93 0 0 0 .934-.923a.93.93 0 0 0-.934-.923z',
  gnubash: siGnubash.path,
  npm: siNpm.path,
  rust: siRust.path,
  homebrew: siHomebrew.path,
  debian: siDebian.path,
  nixos: siNixos.path,
};

const methods = computed(() => installers[selectedOs.value]);
const selectedInstaller = computed(
  () => methods.value.find((item) => item.id === selectedMethod.value) ?? methods.value[0],
);
const variants = computed(() => selectedInstaller.value.variants ?? []);
const activeVariant = computed(
  () => variants.value.find((item) => item.id === selectedVariant.value) ?? variants.value[0],
);
const selectedCommand = computed(() => activeVariant.value?.command ?? selectedInstaller.value.command);
const commandTokens = computed(() => tokenizeCommand(selectedCommand.value));

function iconPath(name: string) {
  return iconSet[name] ?? '';
}

function tokenizeCommand(command: string): CommandToken[] {
  const parts = command.match(/#[^\r\n]*|https?:\/\/[^\s|]+|github:[^\s|;"']+|--?[\w-]+|&&|\||\r?\n|[^\s|]+|[\t ]+/g) ?? [command];
  let expectsCommand = true;

  return parts.map((text) => {
    if (/^\r?\n$/.test(text)) {
      expectsCommand = true;
      return { text, kind: 'space' };
    }
    if (/^[\t ]+$/.test(text)) return { text, kind: 'space' };
    if (text.startsWith('#')) return { text, kind: 'comment' };
    if (text === '|' || text === '&&') {
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
  selectedVariant.value = installers[os][0].variants?.[0]?.id ?? null;
  copyState.value = 'idle';
}

function chooseMethod(method: string) {
  selectedMethod.value = method;
  const installer = methods.value.find((item) => item.id === method);
  selectedVariant.value = installer?.variants?.[0]?.id ?? null;
  copyState.value = 'idle';
}

function chooseVariant(variant: string) {
  selectedVariant.value = variant;
  copyState.value = 'idle';
}

async function copyCommand() {
  try {
    await navigator.clipboard.writeText(selectedCommand.value);
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
          <svg
            class="install-select__icon"
            :data-tone="os.tone"
            aria-hidden="true"
            viewBox="0 0 24 24"
          >
            <path fill="currentColor" :d="iconPath(os.icon)" />
          </svg>
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
          <svg
            class="install-select__icon"
            :data-tone="method.tone"
            aria-hidden="true"
            viewBox="0 0 24 24"
          >
            <path fill="currentColor" :d="iconPath(method.icon)" />
          </svg>
          {{ method.label }}
        </button>
      </div>

      <div
        v-if="variants.length"
        class="install-choice install-choice--variant"
        role="group"
        aria-label="Nix installation mode"
      >
        <span class="install-choice__label">Mode</span>
        <button
          v-for="variant in variants"
          :key="variant.id"
          type="button"
          :class="{ 'is-active': activeVariant?.id === variant.id }"
          :aria-pressed="activeVariant?.id === variant.id"
          @click="chooseVariant(variant.id)"
        >
          {{ variant.label }}
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
