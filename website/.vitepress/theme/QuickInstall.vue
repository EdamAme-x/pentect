<script setup lang="ts">
import { siApple, siLinux } from 'simple-icons';
import { computed, onMounted, ref } from 'vue';

type OperatingSystem = 'windows' | 'macos' | 'linux';

const selectedOs = ref<OperatingSystem>('windows');
const copyState = ref<'idle' | 'copied' | 'failed'>('idle');

const installers = {
  windows: {
    label: 'Windows',
    command: 'irm https://pentect.dev/install | iex',
    icon: 'M0 0h11.377v11.372H0Zm12.623 0H24v11.372H12.623ZM0 12.623h11.377V24H0Zm12.623 0H24V24H12.623',
  },
  macos: {
    label: 'macOS',
    command: 'curl -fsSL https://pentect.dev/install.sh | sh',
    icon: siApple.path,
  },
  linux: {
    label: 'Linux',
    command: 'curl -fsSL https://pentect.dev/install.sh | sh',
    icon: siLinux.path,
  },
};

const installer = computed(() => installers[selectedOs.value]);
const commandTokens = computed(() => tokenizeCommand(installer.value.command));

function tokenizeCommand(command: string) {
  const parts = command.match(/https?:\/\/[^\s|]+|--?[\w-]+|\||[^\s|]+|[\t ]+/g) ?? [command];
  let expectsCommand = true;
  return parts.map((text) => {
    if (/^[\t ]+$/.test(text)) return { text, kind: 'space' };
    if (text === '|') {
      expectsCommand = true;
      return { text, kind: 'operator' };
    }
    if (expectsCommand) {
      expectsCommand = false;
      return { text, kind: 'command' };
    }
    if (text.startsWith('-')) return { text, kind: 'option' };
    if (text.startsWith('http')) return { text, kind: 'string' };
    return { text, kind: 'argument' };
  });
}

async function copyCommand() {
  try {
    await navigator.clipboard.writeText(installer.value.command);
    copyState.value = 'copied';
  } catch {
    copyState.value = 'failed';
  }
}

onMounted(() => {
  const agent = navigator.userAgent.toLowerCase();
  selectedOs.value = agent.includes('mac') ? 'macos' : agent.includes('win') ? 'windows' : 'linux';
});
</script>

<template>
  <section class="quick-install" aria-labelledby="quick-install-heading">
    <div class="quick-install__meta">
      <span id="quick-install-heading">Install</span>
      <span class="quick-install__platform">
        <svg aria-hidden="true" viewBox="0 0 24 24">
          <path fill="currentColor" :d="installer.icon" />
        </svg>
        {{ installer.label }}
      </span>
    </div>

    <div class="quick-install__command">
      <code>
        <span
          v-for="(token, index) in commandTokens"
          :key="`${index}-${token.text}`"
          :class="`shell-token shell-token--${token.kind}`"
        >{{ token.text }}</span>
      </code>
      <button
        type="button"
        class="quick-install__copy"
        :class="{ 'is-copied': copyState === 'copied' }"
        :aria-label="copyState === 'copied' ? 'Copied' : 'Copy install command'"
        :title="copyState === 'copied' ? 'Copied' : 'Copy install command'"
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

    <a class="quick-install__more" href="/start/install/">
      All options <span aria-hidden="true">→</span>
    </a>
    <p v-if="copyState === 'failed'" class="quick-install__status" role="status">
      Select the command and copy it manually.
    </p>
  </section>
</template>
