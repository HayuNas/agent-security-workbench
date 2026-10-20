<script setup lang="ts">
import { computed } from 'vue';
import type { TestTask } from '../types';
import RegressionLibrary from './RegressionLibrary.vue';

const props = defineProps<{task: TestTask; embedded?: boolean}>();
const kind = computed(() => props.task.config.kind === 'attack'
  ? props.task.config.source === 'regression' ? 'security' : 'attack_fixed'
  : props.task.config.source === 'regression' ? 'business_bad' : 'business');
</script>

<template>
  <RegressionLibrary :kind="kind" :task="task" />
</template>
