import { watch, type Ref } from "vue";

/** Navigation resets the default; polling preserves an explicit file choice. */
export function watchReportSelection(
  taskId: () => string, tab: Ref<string>, files: Readonly<Ref<string[]>>, file: Ref<string>,
) {
  return watch([taskId, tab, files], ([id, active, names], previous) => {
    const navigation = !previous || id !== previous[0] || active !== previous[1];
    if (active === "process" || active === "config") {
      file.value = "";
    } else if (navigation || !names.includes(file.value)) {
      file.value = names.find(name => name.endsWith(".md")) || names[0] || "";
    }
  }, { immediate: true });
}
