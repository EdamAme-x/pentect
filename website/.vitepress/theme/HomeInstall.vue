<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';

type OperatingSystem = 'windows' | 'macos' | 'linux';
type Installer = { id: string; label: string; command: string };

const npmInstaller = { id: 'npm', label: 'npm', command: 'npm install --global github:EdamAme-x/pentect' };
const cargoInstaller = {
  id: 'cargo',
  label: 'Cargo',
  command: 'cargo install --git https://github.com/EdamAme-x/pentect --locked pentect-cli',
};

const installers: Record<OperatingSystem, Installer[]> = {
  windows: [
    {
      id: 'powershell',
      label: 'PowerShell',
      command: 'irm https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.ps1 | iex',
    },
    npmInstaller,
    cargoInstaller,
  ],
  macos: [
    { id: 'homebrew', label: 'Homebrew', command: 'brew install EdamAme-x/pentect/pentect' },
    {
      id: 'shell',
      label: 'Shell',
      command: 'curl -fsSL https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.sh | sh',
    },
    npmInstaller,
    { id: 'nix', label: 'Nix profile', command: 'nix profile install github:EdamAme-x/pentect' },
    { id: 'nix-shell', label: 'Nix shell', command: 'nix shell github:EdamAme-x/pentect' },
    cargoInstaller,
  ],
  linux: [
    {
      id: 'shell',
      label: 'Shell',
      command: 'curl -fsSL https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install.sh | sh',
    },
    {
      id: 'apt',
      label: 'APT',
      command: 'curl -fsSL https://raw.githubusercontent.com/EdamAme-x/pentect/main/tools/install-apt.sh | sudo sh',
    },
    npmInstaller,
    { id: 'nix', label: 'Nix profile', command: 'nix profile install github:EdamAme-x/pentect' },
    { id: 'nix-shell', label: 'Nix shell', command: 'nix shell github:EdamAme-x/pentect' },
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

    <div class="home-install__controls">
      <div class="home-install__control" role="group" aria-label="Operating system">
        <span>OS</span>
        <div>
          <button
            v-for="os in (['windows', 'macos', 'linux'] as const)"
            :key="os"
            type="button"
            :aria-pressed="selectedOs === os"
            @click="chooseOs(os)"
          >
            {{ os === 'macos' ? 'macOS' : os[0].toUpperCase() + os.slice(1) }}
          </button>
        </div>
      </div>

      <div class="home-install__control" role="group" aria-label="Installation method">
        <span>Method</span>
        <div>
          <button
            v-for="method in methods"
            :key="method.id"
            type="button"
            :aria-pressed="selectedMethod === method.id"
            @click="chooseMethod(method.id)"
          >
            {{ method.label }}
          </button>
        </div>
      </div>
    </div>

    <div class="home-install__command">
      <code>{{ selectedInstaller.command }}</code>
      <button type="button" @click="copyCommand">
        {{ copyState === 'copied' ? 'Copied' : 'Copy' }}
      </button>
    </div>
    <p v-if="copyState === 'failed'" class="home-install__status" role="status">
      Select the command and copy it manually.
    </p>
  </section>
</template>
