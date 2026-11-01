import { ModeProvider } from "@portfolio/aegis-ui";
import { lazy, Suspense } from "react";
import { HashRouter, Navigate, Route, Routes } from "react-router-dom";
import type { DataSource } from "./api/source";
import { Layout } from "./components/Layout";
import { Loading } from "./components/ui";
import { DataProvider } from "./lib/data";
import WatchFloor from "./pages/WatchFloor";

// Heavier pages load on demand so the first paint of the watch floor stays fast.
const Scenarios = lazy(() => import("./pages/Scenarios"));
const Playback = lazy(() => import("./pages/Playback"));
const Incidents = lazy(() => import("./pages/Incidents"));
const IncidentDetail = lazy(() => import("./pages/IncidentDetail"));
const Coverage = lazy(() => import("./pages/Coverage"));
const Exposure = lazy(() => import("./pages/Exposure"));
const Rules = lazy(() => import("./pages/Rules"));
const Analyst = lazy(() => import("./pages/Analyst"));

// HashRouter keeps deep links working on GitHub Pages, which has no SPA fallback.
export default function App({ source }: { source: DataSource }) {
  return (
    <DataProvider source={source}>
      <ModeProvider product="Watchfloor">
      <HashRouter>
        <Layout>
          <Suspense fallback={<Loading />}>
            <Routes>
              <Route path="/" element={<WatchFloor />} />
              <Route path="/scenarios" element={<Scenarios />} />
              <Route path="/scenarios/:id" element={<Playback />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/incidents/:id" element={<IncidentDetail />} />
              <Route path="/coverage" element={<Coverage />} />
              <Route path="/exposure" element={<Exposure />} />
              <Route path="/rules" element={<Rules />} />
              <Route path="/analyst" element={<Analyst />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </Suspense>
        </Layout>
      </HashRouter>
      </ModeProvider>
    </DataProvider>
  );
}
