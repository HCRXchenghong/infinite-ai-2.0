package app

import (
	"bytes"
	"encoding/json"
	"image"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDecodeGuideMarkerFromPNGLSB(t *testing.T) {
	w, h := 900, 2
	canvas := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := range canvas.Pix {
		canvas.Pix[i] = 0xff
	}
	marker := guideMarker{Version: 1, GuideToken: "fg1.hash.signature", Key: "sk-fg_test", Device: "device-token"}
	payload, err := json.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	frame := append([]byte{'F', 'G', 'P', '1', byte(len(payload) >> 8), byte(len(payload))}, payload...)
	bit := 0
	for x := 0; x < (len(frame)*8+2)/3; x++ {
		pixel := canvas.RGBAAt(x, h-1)
		channels := []*uint8{&pixel.R, &pixel.G, &pixel.B}
		for _, channel := range channels {
			value := byte(0)
			if bit < len(frame)*8 {
				value = (frame[bit/8] >> (7 - bit%8)) & 1
			}
			*channel = (*channel & 0xfe) | value
			bit++
		}
		canvas.SetRGBA(x, h-1, pixel)
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, canvas); err != nil {
		t.Fatal(err)
	}
	got, err := decodeGuideMarker(encoded.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got != marker {
		t.Fatalf("marker mismatch: got %+v want %+v", got, marker)
	}
}

func TestGuideKeyAndPosterAuthentication(t *testing.T) {
	server, store := testApp(t)
	server.cfg.PublicAPIURL = "https://api.example.test/v1"
	server.cfg.PublicGuideURL = "https://guide.example.test"
	plainKey := "sk-fg_guide-key-01234567890123456789"
	createTestAccountAndKey(t, store, "guide-user", plainKey, "198.51.100.91")

	keyRequest := httptest.NewRequest(http.MethodPost, "http://guide.local/api/guide/auth/key", bytes.NewBufferString(`{"key":"`+plainKey+`"}`))
	keyRequest.Header.Set("Content-Type", "application/json")
	keyRequest.RemoteAddr = "198.51.100.91:4000"
	keyResponse := httptest.NewRecorder()
	server.guideHandler().ServeHTTP(keyResponse, keyRequest)
	if keyResponse.Code != http.StatusOK {
		t.Fatalf("key auth status=%d body=%s", keyResponse.Code, keyResponse.Body.String())
	}
	var auth guideAuthResponse
	if err := json.Unmarshal(keyResponse.Body.Bytes(), &auth); err != nil || auth.Key != plainKey || auth.BaseURL == "" {
		t.Fatalf("key auth response=%+v err=%v", auth, err)
	}

	// Recreate the browser's lossless LSB marker and upload it as a PNG poster.
	canvas := image.NewRGBA(image.Rect(0, 0, 900, 2))
	for i := range canvas.Pix {
		canvas.Pix[i] = 0xff
	}
	marker := guideMarker{Version: 1, GuideToken: server.guideTokenForKey(plainKey), Key: plainKey, Device: "device-token-from-poster"}
	payload, _ := json.Marshal(marker)
	frame := append([]byte{'F', 'G', 'P', '1', byte(len(payload) >> 8), byte(len(payload))}, payload...)
	bit := 0
	for x := 0; x < (len(frame)*8+2)/3; x++ {
		pixel := canvas.RGBAAt(x, 1)
		for _, channel := range []*uint8{&pixel.R, &pixel.G, &pixel.B} {
			value := byte(0)
			if bit < len(frame)*8 {
				value = (frame[bit/8] >> (7 - bit%8)) & 1
			}
			*channel = (*channel & 0xfe) | value
			bit++
		}
		canvas.SetRGBA(x, 1, pixel)
	}
	var pngData bytes.Buffer
	if err := png.Encode(&pngData, canvas); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("poster", "friendgate.png")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write(pngData.Bytes())
	_ = form.Close()
	imageRequest := httptest.NewRequest(http.MethodPost, "http://guide.local/api/guide/auth/image", &body)
	imageRequest.Header.Set("Content-Type", form.FormDataContentType())
	imageRequest.RemoteAddr = "198.51.100.91:4000"
	imageResponse := httptest.NewRecorder()
	server.guideHandler().ServeHTTP(imageResponse, imageRequest)
	if imageResponse.Code != http.StatusOK || !bytes.Contains(imageResponse.Body.Bytes(), []byte("device-token-from-poster")) {
		t.Fatalf("poster auth status=%d body=%s", imageResponse.Code, imageResponse.Body.String())
	}
}

func TestGuideModelsRequiresSessionAndUsesOfficialCatalog(t *testing.T) {
	server, store := testApp(t)
	plainKey := "sk-fg_guide-models-01234567890123456789"
	accountID, _ := createTestAccountAndKey(t, store, "guide-models", plainKey, "198.51.100.92")
	installOfficialManifest(t, store, accountID, `{"models":[{"slug":"gpt-5.6-codex"},{"slug":"gpt-image"}]}`)

	unauthorized := httptest.NewRecorder()
	server.guideHandler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "http://guide.local/api/guide/models", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized model catalog status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
	}

	authRequest := httptest.NewRequest(http.MethodPost, "http://guide.local/api/guide/auth/key", bytes.NewBufferString(`{"key":"`+plainKey+`"}`))
	authRequest.Header.Set("Content-Type", "application/json")
	authRequest.RemoteAddr = "198.51.100.92:4000"
	authResponse := httptest.NewRecorder()
	server.guideHandler().ServeHTTP(authResponse, authRequest)
	if authResponse.Code != http.StatusOK {
		t.Fatalf("guide model auth status=%d body=%s", authResponse.Code, authResponse.Body.String())
	}
	cookies := authResponse.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("guide auth did not issue a session cookie")
	}

	modelRequest := httptest.NewRequest(http.MethodGet, "http://guide.local/api/guide/models", nil)
	modelRequest.AddCookie(cookies[0])
	modelResponse := httptest.NewRecorder()
	server.guideHandler().ServeHTTP(modelResponse, modelRequest)
	if modelResponse.Code != http.StatusOK {
		t.Fatalf("guide model catalog status=%d body=%s", modelResponse.Code, modelResponse.Body.String())
	}
	var payload struct {
		Models []ModelDescriptor `json:"models"`
	}
	if err := json.Unmarshal(modelResponse.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Models) != 2 || payload.Models[0].ID != "gpt-5.6-codex" || payload.Models[1].ID != "gpt-image" {
		t.Fatalf("unexpected guide model catalog: %+v", payload.Models)
	}
}
