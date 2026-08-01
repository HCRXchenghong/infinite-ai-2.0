import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const implementations = [
  {
    label: "GUI",
    page: new URL("../../src/pages/skills-hub/SkillsHubPage.tsx", import.meta.url),
    i18n: new URL("../../src/i18n/config.ts", import.meta.url),
  },
  {
    label: "WebUI",
    page: new URL(
      "../../../agent-gateway/web/src/pages/skills-hub/SkillsHubPage.tsx",
      import.meta.url,
    ),
    i18n: new URL("../../../agent-gateway/web/src/i18n/config.ts", import.meta.url),
  },
];

for (const { label, page, i18n } of implementations) {
  const source = readFileSync(page, "utf8");
  const translations = readFileSync(i18n, "utf8");

  test(`${label} defers the initial installed Skills list behind a loading state`, () => {
    assert.match(source, /const deferredSkills = useDeferredValue\(skills, EMPTY_SKILLS\)/);
    assert.match(source, /const installedContentPending = deferredSkills !== skills/);
    assert.match(
      source,
      /skills\.length > 0 && !hasPresentedInstalledSkills && installedContentPending/,
    );
    assert.match(source, /<SkillsContentLoadingState[\s\S]*settings\.skillsHubPreparing/);
    assert.match(source, /aria-busy=\{loading \|\| showInitialInstalledContentLoading\}/);
  });

  test(`${label} runs expensive installed Skill derivation from the deferred snapshot`, () => {
    assert.match(
      source,
      /(?:if \(!text\) return deferredSkills|const matchedSkills = !text\s*\? deferredSkills)/,
    );
    assert.match(source, /(?:return|:) deferredSkills\.filter/);
    assert.doesNotMatch(source, /if \(!text\) return skills/);
  });

  test(`${label} avoids building the discovery signature during the Hub shell render`, () => {
    assert.match(source, /const discoverySignatureRef = useRef<string \| null>\(null\)/);
    assert.doesNotMatch(
      source,
      /const discoverySignatureRef = useRef\(\s*buildSkillDiscoverySignature/,
    );
  });

  test(`${label} includes localized deferred-content loading copy`, () => {
    assert.equal(translations.match(/"settings\.skillsHubPreparing":/g)?.length, 2);
    assert.equal(translations.match(/"settings\.skillsHubPreparingDesc":/g)?.length, 2);
  });
}
