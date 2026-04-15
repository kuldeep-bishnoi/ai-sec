package findings

import "time"

// DedupeByID keeps the first instance of each Finding.ID.
// It preserves input order as much as possible.
func DedupeByID(in []Finding) []Finding {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]Finding, 0, len(in))
	for _, f := range in {
		if f.ID == "" {
			// If something didn't set an ID, keep it (but normalize CreatedAt).
			if f.CreatedAt.IsZero() {
				f.CreatedAt = time.Now()
			}
			out = append(out, f)
			continue
		}
		if _, ok := seen[f.ID]; ok {
			continue
		}
		seen[f.ID] = struct{}{}
		out = append(out, f)
	}
	return out
}
