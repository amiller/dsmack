// Pi uses the root dark class; Abalone defaults to dark unless light is preferred.
const theme = matchMedia("(prefers-color-scheme: light)");
const applyTheme = () => {
  document.documentElement.classList.toggle("dark", !theme.matches);
  document.documentElement.classList.toggle("light", theme.matches);
};
applyTheme();
theme.addEventListener("change", applyTheme);
