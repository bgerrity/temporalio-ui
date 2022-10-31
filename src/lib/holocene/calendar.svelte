<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { noop } from 'svelte/internal';
  import { getDateRows } from '$lib/utilities/calendar';

  const dispatch = createEventDispatcher();

  export let date: Date | undefined;
  export let month: number | undefined;
  export let year: number | undefined;
  export let isAllowed = (_date: Date) => true;

  const weekdays = ['Su', 'Mo', 'Tu', 'We', 'Th', 'Fr', 'Sa'];
  let cells = [];

  const onChange = (date: number) => {
    dispatch('datechange', new Date(year, month, date));
  };

  const allow = (year: number, month: number, date: number) => {
    if (!date) return true;
    return isAllowed(new Date(year, month, date));
  };

  $: cells = getDateRows(month, year).map((c) => ({
    value: c,
    allowed: allow(year, month, c),
  }));
</script>

<div class="container">
  <div class="row">
    {#each weekdays as day}
      <p class="cell">{day}</p>
    {/each}
  </div>

  <div class="row">
    {#each cells as { allowed, value }, index (index)}
      <p
        on:click={allowed && value ? () => onChange(value) : noop}
        class="cell"
        class:highlight={allowed && value}
        class:disabled={!allowed}
        class:selected={new Date(
          date.getFullYear(),
          date.getMonth(),
          date.getDate(),
        ).getTime() === new Date(year, month, value).getTime()}
      >
        {value || ''}
      </p>
    {/each}
  </div>
</div>

<style lang="postcss">
  .container {
    @apply mt-2 h-[224px] w-[265px] px-4;
  }
  .row {
    @apply flex w-[240px] flex-wrap;
  }
  .cell {
    @apply m-1 inline-flex h-[24px] w-[24px] items-center justify-center rounded p-1 text-sm;
  }
  .selected {
    @apply bg-blue-700 text-white;
  }
  .highlight {
    transition: transform 0.2s cubic-bezier(0.165, 0.84, 0.44, 1);
  }
  .disabled {
    background: #efefef;
    cursor: not-allowed;
    color: #bfbfbf;
  }
  .highlight {
    @apply hover:scale-125 hover:cursor-pointer hover:bg-blue-100;
  }
  .selected.highlight:hover {
    @apply bg-blue-700 text-white;
  }
</style>