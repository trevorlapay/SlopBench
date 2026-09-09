// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025-2026 lin-snow

package auth

import "github.com/google/wire"

var ProviderSet = wire.NewSet(
	NewAuthService,
	wire.Bind(new(Service), new(*AuthService)),
)
