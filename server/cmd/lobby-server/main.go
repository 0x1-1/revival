// Lobby server -- between login and battle.
//
// Goley flow:
//   Entry server validates credentials → returns lobby endpoint
//   Client connects to lobby → RequestNextLogon(credential)
//   Lobby publishes game rooms, chat, friend list
//   Client creates/joins room → server returns battle endpoint + new credential
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/uintptr/goley-server/internal/proudnet"
)

const defaultAddr = "0.0.0.0:2271"

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(log)

	addr := defaultAddr
	if v := os.Getenv("LOBBY_ADDR"); v != "" {
		addr = v
	}

	srv := proudnet.NewServer(addr, log.With("svc", "lobby"))
	registerHandlers(srv, log)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Info("lobby server starting", "addr", addr)
	if err := srv.ListenAndServe(ctx); err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}

func registerHandlers(s *proudnet.Server, log *slog.Logger) {
	// LobbyC2S.RequestNextLogon -- credential from entry server
	s.Handle(proudnet.LobbyC2S_RequestNextLogon, func(c *proudnet.Conn, body *proudnet.Message) error {
		credential, err := body.ReadBytes(16)
		if err != nil {
			return err
		}
		log.Info("lobby logon", "hostID", c.HostID, "cred_len", len(credential))

		// Accept; reply with NotifyNextLogonSuccess + a HeroPublishInfo blob.
		// CHeroPublishInfo is a custom struct -- placeholder for now.
		resp := proudnet.NewMessage()
		resp.WriteBytes(make([]byte, 16)) // GamerGuid
		resp.WriteString("Goley")          // hero name (stand-in for full CHeroPublishInfo)
		return c.Send(proudnet.LobbyS2C_NotifyNextLogonSuccess, resp)
	})

	// LobbyC2S.Chat -- broadcast chat to everyone in lobby
	s.Handle(proudnet.LobbyC2S_Chat, func(c *proudnet.Conn, body *proudnet.Message) error {
		text, err := body.ReadString()
		if err != nil {
			return err
		}
		log.Info("lobby chat", "from", c.HostID, "text", text)
		// Broadcast as ShowChat([Guid heroGuid, String chatText])
		s.Broadcast(proudnet.LobbyS2C_ShowChat, func() *proudnet.Message {
			m := proudnet.NewMessage()
			m.WriteBytes(make([]byte, 16)) // sender heroGuid placeholder
			m.WriteString(text)
			return m
		})
		return nil
	})

	// LobbyC2S.RequestCreateGameRoom -- create a new room
	s.Handle(proudnet.LobbyC2S_RequestCreateGameRoom, func(c *proudnet.Conn, body *proudnet.Message) error {
		log.Info("create room request", "hostID", c.HostID)
		// CGameRoomParameter is custom -- placeholder
		resp := proudnet.NewMessage()
		resp.WriteString("Room 1")    // room name
		resp.WriteString("127.0.0.1") // battle server
		resp.WriteInt32(2272)         // port
		return c.Send(proudnet.LobbyS2C_NotifyCreateRoomSuccess, resp)
	})
}
