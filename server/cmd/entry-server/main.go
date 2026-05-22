// Entry server -- login and character selection.
//
// Mirror of ProudNet CasualGame2 "EntryServer" sample, adapted for Goley.
// Listens on a TCP port; handles RequestFirstLogon, RequestHeroSlots, etc.
//
// Default port 2270 (matches original Joygame login server port hint).
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/uintptr/goley-server/cmd/database"
	"github.com/uintptr/goley-server/internal/proudnet"
)

const defaultAddr = "0.0.0.0:2270"

var (
	db *database.Database
)

func main() {
	db := database.ConnectDatabase()
	db.CheckTables()
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(log)

	addr := defaultAddr
	if v := os.Getenv("ENTRY_ADDR"); v != "" {
		addr = v
	}

	srv := proudnet.NewServer(addr, log.With("svc", "entry"))
	registerHandlers(srv, log)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Info("entry server starting", "addr", addr)
	if err := srv.ListenAndServe(ctx); err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}

func registerHandlers(s *proudnet.Server, log *slog.Logger) {
	// Hand maded register handler
	// TODO Implement client side and test this request
	s.Handle(proudnet.EntryC2S_RequestCreateNewGamer, func(c *proudnet.Conn, body *proudnet.Message) error {
		gamerID, err := body.ReadString()
		if err != nil {
			return err
		}
		password, _ := body.ReadString()
		log.Info("RequestRegister", " id: ", gamerID, " pw_len: ", len(password))

		err = db.RegisterUser(gamerID, password)
		if err != nil {
			log.Error("Player: ", gamerID, " database register error.")
			resp := proudnet.NewMessage()
			return c.Send(proudnet.EntryS2C_NotifyCreateNewGamerFailed, resp)
		}
		resp := proudnet.NewMessage()
		return c.Send(proudnet.EntryS2C_NotifyCreateNewGamerSuccess, resp)
	})
	// Goley-specific: RequestLogin (Goley uses this, not RequestFirstLogon)
	s.Handle(proudnet.EntryC2S_RequestLogin, func(c *proudnet.Conn, body *proudnet.Message) error {
		gamerID, err := body.ReadString()
		if err != nil {
			return err
		}
		password, _ := body.ReadString()
		log.Info("RequestLogin", "id", gamerID, "pw_len", len(password))
		// NotifyLoginOk (Goley) -- gamerGuid + credential
		// TODO Create a user struct after this for sanity checks like for EntryC2S_RequestHeroSlots etc. requests
		_, err = db.GetUser(gamerID, password)
		if err != nil {
			log.Info("RequestLogin", "id", gamerID, "pw_len", len(password))
			resp := proudnet.NewMessage()
			return c.Send(proudnet.EntryS2C_NotifyLoginFailed, resp)
		}
		resp := proudnet.NewMessage()
		resp.WriteBytes(makeFakeGuid(gamerID))
		resp.WriteBytes(makeFakeGuid("cred_" + gamerID))
		return c.Send(proudnet.EntryS2C_NotifyLoginOk, resp)
	})

	// EntryC2S.RequestFirstLogon (CasualGame2 sample style, kept as fallback)
	s.Handle(proudnet.EntryC2S_RequestFirstLogon, func(c *proudnet.Conn, body *proudnet.Message) error {
		gamerID, err := body.ReadString()
		if err != nil {
			return err
		}
		password, err := body.ReadString()
		if err != nil {
			return err
		}
		log.Info("login attempt", "id", gamerID, "pw_len", len(password))

		// Always succeed for now -- credential is a fake GUID
		resp := proudnet.NewMessage()
		// NotifyFirstLogonSuccess([in] Guid Gamerguid, [in] Guid credential)
		// Guid = 16 bytes; we use a simple deterministic stub for now.
		gamerGuid := makeFakeGuid(gamerID)
		credential := makeFakeGuid("credential_" + gamerID)
		resp.WriteBytes(gamerGuid)
		resp.WriteBytes(credential)
		return c.Send(proudnet.EntryS2C_NotifyFirstLogonSuccess, resp)
	})

	// EntryC2S.RequestHeroSlots -- return a dummy hero list
	s.Handle(proudnet.EntryC2S_RequestHeroSlots, func(c *proudnet.Conn, body *proudnet.Message) error {
		// HeroList_Begin
		c.Send(proudnet.EntryS2C_HeroList_Begin, proudnet.NewMessage())
		// HeroList_Add([in] CStringW heroName, [in] Guid heroGuid, [in] int heroType, [in] LONGLONG heroScore)
		add := proudnet.NewMessage()
		add.WriteString("Goley")
		add.WriteBytes(makeFakeGuid("hero_default"))
		add.WriteInt32(1)    // heroType
		add.WriteInt64(1000) // heroScore
		c.Send(proudnet.EntryS2C_HeroList_Add, add)
		// HeroList_End
		return c.Send(proudnet.EntryS2C_HeroList_End, proudnet.NewMessage())
	})

	// EntryC2S.RequestLobbyList -- return one lobby pointing at 127.0.0.1:2271
	s.Handle(proudnet.EntryC2S_RequestLobbyList, func(c *proudnet.Conn, body *proudnet.Message) error {
		c.Send(proudnet.EntryS2C_LobbyList_Begin, proudnet.NewMessage())
		add := proudnet.NewMessage()
		// LobbyList_Add([in] CStringW lobbyName, [in] NamedAddrPort serverAddr, [in] int gamerCount)
		add.WriteString("Goley Lobby")
		// NamedAddrPort serialization: name + addr + port (placeholder).
		add.WriteString("127.0.0.1")
		add.WriteInt32(2271)
		add.WriteInt32(0) // gamerCount
		c.Send(proudnet.EntryS2C_LobbyList_Add, add)
		return c.Send(proudnet.EntryS2C_LobbyList_End, proudnet.NewMessage())
	})
}

// makeFakeGuid returns a 16-byte deterministic GUID-shaped identifier built
// from a string seed. Sufficient for prototype login flow; production should
// use real GUIDs.
func makeFakeGuid(seed string) []byte {
	out := make([]byte, 16)
	for i, b := range []byte(seed) {
		out[i%16] ^= b
	}
	return out
}
