import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createWebModuleLoader } from "../../test/helpers/load-web-module.mjs";

const loader = createWebModuleLoader({
  rootDir: fileURLToPath(new URL("../", import.meta.url)),
});
const thinking = loader.loadModule("src/lib/models/modelThinking.ts");
const settings = loader.loadModule("src/lib/settings/index.ts");

// 镜像强制：与 GUI 端字节一致（mirror manifest 也管，但这里在测试层再锁一次，
// 防止只跑单端测试时漂移漏检）。
test("modelThinking.ts is byte-identical across both frontends", () => {
  const webPath = fileURLToPath(new URL("../src/lib/models/modelThinking.ts", import.meta.url));
  const guiPath = fileURLToPath(
    new URL("../../../agent-gui/src/lib/models/modelThinking.ts", import.meta.url),
  );
  const digest = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
  assert.equal(digest(webPath), digest(guiPath));
});

test("web thinking wrappers delegate to the shared resolver", () => {
  assert.deepEqual(settings.getKnownModelThinkingLevels("claude_code", "claude-sonnet-4-6"), [
    "low",
    "medium",
    "high",
    "max",
  ]);
  assert.equal(settings.isThinkingAlwaysOnForModel("claude_code", "claude-sonnet-4-6"), false);
  assert.equal(settings.isThinkingAlwaysOnForModel("xai", "grok-4.5"), true);
  assert.equal(settings.isThinkingAlwaysOnForModel("codex", "gpt-5"), true);
  assert.deepEqual(settings.getKnownModelThinkingLevels("codex", "gpt-4o"), []);
  // 恒开不可调（中转挂载）：无档位但思考恒开
  assert.deepEqual(settings.getKnownModelThinkingLevels("claude_code", "deepseek-reasoner"), []);
  assert.equal(settings.isThinkingAlwaysOnForModel("claude_code", "deepseek-reasoner"), true);
});

test("web resolver honors decorated ids and heuristics like the GUI", () => {
  assert.deepEqual(
    thinking.resolveModelThinking("claude_code", "claude-sonnet-4-6-20251114").levels,
    ["low", "medium", "high", "max"],
  );
  assert.deepEqual(thinking.resolveModelThinking("claude_code", "claude-4.7-opus").levels, [
    "low",
    "medium",
    "high",
    "xhigh",
    "max",
  ]);
});
