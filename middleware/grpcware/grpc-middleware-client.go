package grpcware

import (
	"context"
	"fmt"

	"github.com/mamaart/jwtengine/middleware"
	"github.com/mamaart/jwtengine/validator"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type Middleware struct {
	*validator.Validator
}

func (m *Middleware) UnaryClientInterceptor(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	claims, err := middleware.ContextGetClaims(ctx)
	if err != nil {
		return fmt.Errorf("token not set in context: %w", err)
	}

	myMap := make(map[string]string)

	for k, v := range claims {
		myMap[k] = fmt.Sprintf("%v", v)
	}

	ctx = metadata.NewOutgoingContext(ctx, metadata.New(myMap))

	fmt.Println("* gRPC CLIENT middleware set token")

	return invoker(ctx, method, req, reply, cc, opts...)
}
