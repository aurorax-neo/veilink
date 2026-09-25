// Copyright (c) Xray-core contributors.
// Copyright (c) 2026 Veilink contributors (adaptation).
// SPDX-License-Identifier: MPL-2.0
//
// Adapted from Xray-core transport/internet/hysteria/congestion/utils.go,
// commit d562d8947d3175db86b4fa849742433a9876cb63.
// Changes: narrow connection interface, fixed standard profile, no Brutal/Reno.
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. See https://mozilla.org/MPL/2.0/ and NOTICE.
package tunnel

import (
	"net"

	"github.com/apernet/quic-go/congestion"
	"github.com/xtls/xray-core/transport/internet/hysteria/congestion/bbr"
)

type hysteriaCongestionConn interface {
	InitialPacketSize() congestion.ByteCount
	RemoteAddr() net.Addr
	SetCongestionControl(congestion.CongestionControl)
}

// enableHysteriaBBR runs once after HY2 authentication, before business streams,
// on both endpoints, matching Xray's authenticated HY2 switching point.
func enableHysteriaBBR(conn hysteriaCongestionConn) {
	packetSize := bbr.GetInitialPacketSize(conn.RemoteAddr())
	if initial := conn.InitialPacketSize(); initial > 0 {
		packetSize = min(initial, packetSize)
	}
	conn.SetCongestionControl(bbr.NewBbrSender(bbr.DefaultClock{}, packetSize, bbr.ProfileStandard))
}
