export const TASK_PAGE_SIZE = 10;

export function sidebarWindow(page: number, draftCount: number) {
  const start = (page - 1) * TASK_PAGE_SIZE;
  const drafts = Math.min(TASK_PAGE_SIZE, Math.max(0, draftCount - start));
  return { draftStart: start, drafts, offset: Math.max(0, start - draftCount), limit: TASK_PAGE_SIZE - drafts };
}
