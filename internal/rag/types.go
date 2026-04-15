package rag

type Chunk struct {
	ID        string    `json:"id"`
	File      string    `json:"file"`
	StartLine int       `json:"start_line"`
	EndLine   int       `json:"end_line"`
	Language  string    `json:"language"`
	Text      string    `json:"text"`
	Embedding []float32 `json:"embedding,omitempty"`
}

type IndexMeta struct {
	EmbeddingProvider string `json:"embedding_provider"`
	EmbeddingModel    string `json:"embedding_model"`
	HasEmbeddings     bool   `json:"has_embeddings"`
}
