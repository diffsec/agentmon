package policy

import "context"

type stubInspector struct{}

func (stubInspector) Inspect(context.Context, InspectRequest) (InspectVerdict, error) {
	return InspectVerdict{}, nil
}
