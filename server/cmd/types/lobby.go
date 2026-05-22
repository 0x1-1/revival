package types

type Lobby struct {
	LobbyIP        string
	LobbyPort      int32
	LobbyName      string
	GamerCount     int32
	IsGameFull     bool
	IsMatchStarted bool
}
