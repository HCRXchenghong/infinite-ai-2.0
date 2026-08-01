import assert from "node:assert/strict";
import test from "node:test";
import { createGatewayV2Codec } from "../helpers/gateway-v2.mjs";
import { createWebModuleLoader } from "../helpers/load-web-module.mjs";

const requestCalls = [];
const testCalls = [];
const loader = createWebModuleLoader({
  mocks: {
    "@/lib/gatewaySocket": {
      getGatewayWebSocketClient() {
        return {
          providerUsageQuery(providerId, refresh) {
            requestCalls.push({ providerId, refresh });
            return Promise.resolve({
              data: [{ planName: "Credits", remaining: 11, unit: "USD" }],
              queriedAt: 123,
              error: null,
              isStale: false,
            });
          },
          providerUsageTest(providerId, configJson) {
            testCalls.push({ providerId, configJson });
            return Promise.resolve({
              data: [{ planName: "Draft", remaining: 3, unit: "USD" }],
              queriedAt: 456,
              error: null,
              isStale: false,
            });
          },
        };
      },
    },
    "@/lib/storage": { loadToken: () => "gateway-token" },
  },
});
const usage = loader.loadModule("src/lib/providers/usageQuery.ts");
const adapters = loader.loadModule("src/lib/gatewaySocketV2/adapters.ts");
const codec = createGatewayV2Codec(loader);

test("WebUI query client refreshes one provider through the Gateway", async () => {
  requestCalls.length = 0;

  const result = await usage.queryProviderUsage("provider-a", true);

  assert.equal(result.data[0].remaining, 11);
  assert.deepEqual(requestCalls, [{ providerId: "provider-a", refresh: true }]);
});

test("WebUI draft test forwards the editor config JSON to the desktop", async () => {
  testCalls.length = 0;

  const result = await usage.testProviderUsage("provider-a", { enabled: false, mode: "custom" });

  assert.equal(result.data[0].planName, "Draft");
  assert.deepEqual(testCalls, [
    { providerId: "provider-a", configJson: '{"enabled":false,"mode":"custom"}' },
  ]);
});

test("WebUI protobuf encodes usage request and decodes JSON response", () => {
  const request = codec.decodeClientFrame(
    adapters.encodeRequestFrame(
      "request-1",
      "provider.usage.query",
      { provider_id: "provider-a", refresh: true },
      "desktop-agent",
    ),
  );

  assert.equal(request.case, "agentRequest");
  assert.deepEqual(request.json.agent_request.provider_usage, {
    provider_id: "provider-a",
    refresh: true,
  });

  // 按草稿测试:config_json 随请求透传。
  const draftRequest = codec.decodeClientFrame(
    adapters.encodeRequestFrame(
      "request-9",
      "provider.usage.query",
      { provider_id: "provider-a", refresh: true, config_json: '{"mode":"custom"}' },
      "desktop-agent",
    ),
  );
  assert.equal(
    draftRequest.json.agent_request.provider_usage.config_json,
    '{"mode":"custom"}',
  );

  const frame = codec.encodeServerFrame({
    request_id: "request-1",
    agent_id: "desktop-agent",
    agent_response: {
      provider_usage_resp: {
        result_json: JSON.stringify({
          data: [{ planName: "Credits", remaining: 11, unit: "USD" }],
          queriedAt: 123,
          error: null,
          isStale: false,
        }),
      },
    },
  });
  const decoded = adapters.decodeServerFrame(adapters.decodeServerFrameBinary(frame), {
    agentOnline: true,
  });

  assert.deepEqual(decoded, {
    kind: "response",
    requestId: "request-1",
    agentId: "desktop-agent",
    payload: {
      data: [{ planName: "Credits", remaining: 11, unit: "USD" }],
      queriedAt: 123,
      error: null,
      isStale: false,
    },
  });
});

test("WebUI protobuf rejects malformed usage response JSON", () => {
  const frame = codec.encodeServerFrame({
    request_id: "request-2",
    agent_id: "desktop-agent",
    agent_response: {
      provider_usage_resp: { result_json: "{not-json" },
    },
  });

  const decoded = adapters.decodeServerFrame(adapters.decodeServerFrameBinary(frame), {
    agentOnline: true,
  });

  assert.deepEqual(decoded, {
    kind: "error",
    requestId: "request-2",
    agentId: "desktop-agent",
    message: "provider usage response is not valid JSON",
  });
});
