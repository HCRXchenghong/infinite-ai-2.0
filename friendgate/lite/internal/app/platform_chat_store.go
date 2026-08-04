package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type PlatformChatConversation struct {
	ID               string     `json:"id"`
	UserID           string     `json:"user_id"`
	Title            string     `json:"title"`
	SelectedModelKey string     `json:"selected_model_key"`
	Status           string     `json:"status"`
	LastMessageAt    *time.Time `json:"last_message_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type PlatformChatMessage struct {
	ID             string          `json:"id"`
	ConversationID string          `json:"conversation_id"`
	UserID         string          `json:"user_id"`
	Role           string          `json:"role"`
	Text           string          `json:"text"`
	Content        json.RawMessage `json:"content"`
	ModelKey       string          `json:"model_key"`
	RequestID      string          `json:"request_id,omitempty"`
	Status         string          `json:"status"`
	ErrorCode      string          `json:"error_code,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
}

type PlatformChatConversationInput struct {
	Title            string `json:"title"`
	SelectedModelKey string `json:"selected_model_key"`
}

type PlatformChatConversationPatch struct {
	Title            *string `json:"title,omitempty"`
	SelectedModelKey *string `json:"selected_model_key,omitempty"`
	Status           *string `json:"status,omitempty"`
}

type PlatformChatMessageInput struct {
	ConversationID string
	UserID         string
	Role           string
	Text           string
	Content        json.RawMessage
	ModelKey       string
	RequestID      string
	Status         string
	ErrorCode      string
}

func (s *PlatformStore) CreatePlatformChatConversation(ctx context.Context, userID string, input PlatformChatConversationInput) (*PlatformChatConversation, error) {
	userID = strings.TrimSpace(userID)
	title := normalizePlatformChatTitle(input.Title)
	modelKey := truncate(strings.TrimSpace(input.SelectedModelKey), 128)
	if userID == "" {
		return nil, ErrInvalidPlatformModel
	}
	item := &PlatformChatConversation{ID: newPlatformID(), UserID: userID, Title: title, SelectedModelKey: modelKey, Status: "active"}
	err := s.db.QueryRowContext(ctx, `INSERT INTO chat_conversations(id,user_id,title,selected_model_key,status)
SELECT $1,$2,$3,$4,'active' WHERE EXISTS(SELECT 1 FROM users WHERE id=$2 AND status='active')
RETURNING created_at,updated_at`, item.ID, item.UserID, item.Title, item.SelectedModelKey).Scan(&item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return item, nil
}

func (s *PlatformStore) ListPlatformChatConversations(ctx context.Context, userID string, limit int) ([]PlatformChatConversation, error) {
	userID = strings.TrimSpace(userID)
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id::text,user_id::text,title,selected_model_key,status,last_message_at,created_at,updated_at
FROM chat_conversations WHERE user_id=$1 AND status<>'deleted'
ORDER BY COALESCE(last_message_at,updated_at) DESC,id DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformChatConversation, 0)
	for rows.Next() {
		var item PlatformChatConversation
		var last sql.NullTime
		if err := rows.Scan(&item.ID, &item.UserID, &item.Title, &item.SelectedModelKey, &item.Status, &last, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		if last.Valid {
			value := last.Time
			item.LastMessageAt = &value
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PlatformStore) PlatformChatConversation(ctx context.Context, userID, conversationID string) (*PlatformChatConversation, []PlatformChatMessage, error) {
	item := &PlatformChatConversation{}
	var last sql.NullTime
	err := s.db.QueryRowContext(ctx, `SELECT id::text,user_id::text,title,selected_model_key,status,last_message_at,created_at,updated_at
FROM chat_conversations WHERE id=$1 AND user_id=$2 AND status<>'deleted'`, strings.TrimSpace(conversationID), strings.TrimSpace(userID)).Scan(&item.ID, &item.UserID, &item.Title, &item.SelectedModelKey, &item.Status, &last, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	if last.Valid {
		value := last.Time
		item.LastMessageAt = &value
	}
	messages, err := s.ListPlatformChatMessages(ctx, userID, conversationID)
	if err != nil {
		return nil, nil, err
	}
	return item, messages, nil
}

func (s *PlatformStore) UpdatePlatformChatConversation(ctx context.Context, userID, conversationID string, patch PlatformChatConversationPatch) (*PlatformChatConversation, error) {
	userID, conversationID = strings.TrimSpace(userID), strings.TrimSpace(conversationID)
	if userID == "" || conversationID == "" {
		return nil, ErrInvalidPlatformModel
	}
	var title, modelKey, status any
	if patch.Title != nil {
		title = normalizePlatformChatTitle(*patch.Title)
	}
	if patch.SelectedModelKey != nil {
		modelKey = truncate(strings.TrimSpace(*patch.SelectedModelKey), 128)
	}
	if patch.Status != nil {
		value := strings.TrimSpace(*patch.Status)
		if value != "active" && value != "archived" && value != "deleted" {
			return nil, ErrInvalidPlatformModel
		}
		status = value
	}
	if title == nil && modelKey == nil && status == nil {
		return nil, ErrInvalidPlatformModel
	}
	item := &PlatformChatConversation{}
	var last sql.NullTime
	err := s.db.QueryRowContext(ctx, `UPDATE chat_conversations SET title=COALESCE($3,title),selected_model_key=COALESCE($4,selected_model_key),status=COALESCE($5,status),updated_at=now()
WHERE id=$1 AND user_id=$2 AND status<>'deleted'
RETURNING id::text,user_id::text,title,selected_model_key,status,last_message_at,created_at,updated_at`, conversationID, userID, title, modelKey, status).Scan(&item.ID, &item.UserID, &item.Title, &item.SelectedModelKey, &item.Status, &last, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if last.Valid {
		value := last.Time
		item.LastMessageAt = &value
	}
	return item, nil
}

func (s *PlatformStore) ListPlatformChatMessages(ctx context.Context, userID, conversationID string) ([]PlatformChatMessage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT m.id::text,m.conversation_id::text,m.user_id::text,m.role,m.text,m.content,m.model_key,m.request_id,m.status,m.error_code,m.created_at
FROM chat_messages m JOIN chat_conversations c ON c.id=m.conversation_id AND c.user_id=m.user_id
WHERE m.conversation_id=$1 AND m.user_id=$2 AND c.status<>'deleted'
ORDER BY m.created_at,m.id`, strings.TrimSpace(conversationID), strings.TrimSpace(userID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PlatformChatMessage, 0)
	for rows.Next() {
		var item PlatformChatMessage
		if err := rows.Scan(&item.ID, &item.ConversationID, &item.UserID, &item.Role, &item.Text, &item.Content, &item.ModelKey, &item.RequestID, &item.Status, &item.ErrorCode, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PlatformStore) AppendPlatformChatMessage(ctx context.Context, input PlatformChatMessageInput) (*PlatformChatMessage, error) {
	input.ConversationID = strings.TrimSpace(input.ConversationID)
	input.UserID = strings.TrimSpace(input.UserID)
	input.Role = strings.TrimSpace(input.Role)
	input.Text = truncate(strings.TrimSpace(input.Text), 256<<10)
	input.ModelKey = truncate(strings.TrimSpace(input.ModelKey), 128)
	input.RequestID = truncate(strings.TrimSpace(input.RequestID), 160)
	input.Status = strings.TrimSpace(input.Status)
	input.ErrorCode = truncate(strings.TrimSpace(input.ErrorCode), 120)
	if input.ConversationID == "" || input.UserID == "" || (input.Role != "user" && input.Role != "assistant" && input.Role != "system" && input.Role != "tool") {
		return nil, ErrInvalidPlatformModel
	}
	if input.Status == "" {
		input.Status = "sent"
	}
	if input.Status != "sent" && input.Status != "error" {
		return nil, ErrInvalidPlatformModel
	}
	if len(input.Content) == 0 {
		input.Content = platformChatTextContent(input.Text)
	}
	if len(input.Content) > 512<<10 || !isJSONObject(input.Content) {
		return nil, ErrInvalidPlatformModel
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	item := &PlatformChatMessage{ID: newPlatformID(), ConversationID: input.ConversationID, UserID: input.UserID, Role: input.Role, Text: input.Text, Content: append([]byte(nil), input.Content...), ModelKey: input.ModelKey, RequestID: input.RequestID, Status: input.Status, ErrorCode: input.ErrorCode}
	err = tx.QueryRowContext(ctx, `INSERT INTO chat_messages(id,conversation_id,user_id,role,text,content,model_key,request_id,status,error_code)
SELECT $1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10
WHERE EXISTS(SELECT 1 FROM chat_conversations c JOIN users u ON u.id=c.user_id WHERE c.id=$2 AND c.user_id=$3 AND c.status='active' AND u.status='active')
RETURNING created_at`, item.ID, item.ConversationID, item.UserID, item.Role, item.Text, string(item.Content), item.ModelKey, item.RequestID, item.Status, item.ErrorCode).Scan(&item.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE chat_conversations SET last_message_at=$3,updated_at=now(),selected_model_key=COALESCE(NULLIF($4,''),selected_model_key) WHERE id=$1 AND user_id=$2`, item.ConversationID, item.UserID, item.CreatedAt, item.ModelKey); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return item, nil
}

func normalizePlatformChatTitle(value string) string {
	value = strings.Join(strings.Fields(strings.TrimSpace(value)), " ")
	if value == "" {
		return "新对话"
	}
	return truncate(value, 160)
}

func platformChatTextContent(text string) json.RawMessage {
	raw, _ := json.Marshal(map[string]string{"text": text})
	return raw
}
