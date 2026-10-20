import { createApp } from "vue";
import App from "./App.vue";
import "./styles.css";

// 整个应用从这里启动：App 管布局，组件管界面，store 管任务数据。
createApp(App).mount("#app");
