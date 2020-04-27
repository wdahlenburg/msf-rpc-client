package main

import (
	"bufio"
	"fmt"
	"github.com/wdahlenburg/msf-rpc-client/rpc"
	"log"
	"os"
)

func main() {
	host := os.Getenv("MSFHOST")
	user := "msf"
	pass := os.Getenv("MSFPASS")

	commands := []string{}

	if host == "" || pass == "" {
		log.Fatalln("Missing required environment variable MSFHOST or MSFPASS")
	}

	if len(os.Args) == 2 {
		file, err := os.Open(os.Args[1])
		if err != nil {
			log.Fatalln(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			commands = append(commands, scanner.Text())
		}
	}

	msf, err := rpc.New(host, user, pass)
	if err != nil {
		log.Panicln(err)
	}
	defer msf.Logout()

	sessions, err := msf.SessionList()
	if err != nil {
		log.Panicln(err)
	}
	fmt.Println("Sessions:")
	for _, session := range sessions {
		fmt.Printf("%5d  %s\n", session.ID, session.Info)
		if len(commands) > 0 {
			data, err := msf.SessionExecuteList(session.ID, commands)
			if err != nil {
				log.Fatalln(err)
			}
			fmt.Printf("%s", data)
		}
	}
}
