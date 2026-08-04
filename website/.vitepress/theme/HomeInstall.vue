<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';

type OperatingSystem = 'windows' | 'macos' | 'linux';
type Installer = { id: string; label: string; command: string; icon: string; tone: string };

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
      command: 'irm https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.ps1 | iex',
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
      command: 'curl -fsSL https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.sh | sh',
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
      command: 'curl -fsSL https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.sh | sh',
      icon: '$_',
      tone: 'shell',
    },
    {
      id: 'apt',
      label: 'APT',
      command: 'curl -fsSL https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install-apt.sh | sudo sh',
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
const selectedOperatingSystem = computed(
  () => operatingSystems.find((item) => item.id === selectedOs.value) ?? operatingSystems[0],
);
const selectedInstaller = computed(
  () => methods.value.find((item) => item.id === selectedMethod.value) ?? methods.value[0],
);

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
      <div>
        <p>Install</p>
        <h2 id="install-heading">Start with one command.</h2>
      </div>
      <a href="/start/install/">All options <span aria-hidden="true">→</span></a>
    </div>

    <p class="home-install__sentence">
      <span>Install Pentect for</span>
      <label class="install-select">
        <span
          class="install-select__icon"
          :data-tone="selectedOperatingSystem.tone"
          aria-hidden="true"
        >{{ selectedOperatingSystem.icon }}</span>
        <select
          v-model="selectedOs"
          aria-label="Operating system"
          @change="chooseOs(selectedOs)"
        >
          <option v-for="os in operatingSystems" :key="os.id" :value="os.id">
            {{ os.label }}
          </option>
        </select>
        <span class="install-select__chevron" aria-hidden="true">⌄</span>
      </label>
      <span>using</span>
      <label class="install-select">
        <span
          class="install-select__icon"
          :data-tone="selectedInstaller.tone"
          aria-hidden="true"
        >{{ selectedInstaller.icon }}</span>
        <select
          v-model="selectedMethod"
          aria-label="Installation method"
          @change="chooseMethod(selectedMethod)"
        >
          <option v-for="method in methods" :key="method.id" :value="method.id">
            {{ method.label }}
          </option>
        </select>
        <span class="install-select__chevron" aria-hidden="true">⌄</span>
      </label>
    </p>

    <div class="home-install__command">
      <div class="home-install__code">
        <code>{{ selectedInstaller.command }}</code>
      </div>
      <div class="home-install__command-footer">
        <span>
          <i
            class="install-select__icon"
            :data-tone="selectedInstaller.tone"
            aria-hidden="true"
          >{{ selectedInstaller.icon }}</i>
          {{ selectedInstaller.label }}
        </span>
        <button type="button" @click="copyCommand">
          <span aria-hidden="true">▣</span>
          {{ copyState === 'copied' ? 'Copied' : 'Copy command' }}
        </button>
      </div>
    </div>
    <p v-if="copyState === 'failed'" class="home-install__status" role="status">
      Select the command and copy it manually.
    </p>
  </section>
</template>
