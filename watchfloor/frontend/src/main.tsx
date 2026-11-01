import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { detectSource } from "./api/source";
import "./index.css";

const root = createRoot(document.getElementById("root") as HTMLElement);

detectSource().then((source) => {
  root.render(
    <StrictMode>
      <App source={source} />
    </StrictMode>,
  );
});
