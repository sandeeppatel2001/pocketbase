// Prefer a static wrapper instead of reflect.MakeFunc
func makeHandler(handler func(ctx context.Context, args []string) ([]any, error)) func(context.Context, []string) ([]any, error) {
	return func(ctx context.Context, args []string) ([]any, error) {
		if len(args) > maxArgs {
			return nil, fmt.Errorf("too many arguments")
		}
		return handler(ctx, args)
	}
}


switch method.Name {
case "AllowedHookA":
	hookInstance = appValue.MethodByName("AllowedHookA").Call(tagsAsValues)[0]
case "AllowedHookB":
	hookInstance = appValue.MethodByName("AllowedHookB").Call(tagsAsValues)[0]
default:
	return nil, fmt.Errorf("unsupported method")
}
