package main

type MyClaims struct {
	user string
}

func (c *MyClaims) AccessClaimsAsMap() map[string]interface{} {
	return map[string]interface{}{
		"user": c.user,
	}
}
func (c *MyClaims) RefreshClaimsAsMap() map[string]interface{} {
	return map[string]interface{}{
		"user": c.user,
	}
}

type RefreshValidator struct {
}

func (v *RefreshValidator) Validate(map[string]interface{}) (*MyClaims, error) {
	return &MyClaims{
		user: "refreshed",
	}, nil
}
