// Pi uses the root dark class; follow the browser's theme, including changes.
const theme = matchMedia("(prefers-color-scheme: dark)");
const applyTheme = () => document.documentElement.classList.toggle("dark", theme.matches);
applyTheme();
theme.addEventListener("change", applyTheme);
