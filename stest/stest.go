package main

import (
	"fmt"
	"html/template"
	"net"
	"net/http"
)

var (
	temps           *template.Template
	Harici          = "Harici"
	gelenMesajKanal = make(chan string)
	gidenMesajKanal = make(chan string)
)

func init() {

	temps = template.Must(template.ParseGlob("../tmpl/*.templ"))

}

func serVer(input chan<- string) {

	tcpAddr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%s", "4444"))
	fmt.Println("IP add: ", tcpAddr)
	listener, _ := net.ListenTCP("tcp", tcpAddr)

	for {
		// defer close(input)
		connectTo, _ := listener.Accept()
		in := make([]byte, 1024)
		nRead, _ := connectTo.Read(in[:])
		msgIn := in[:nRead]
		msgserVer := string(msgIn)
		fmt.Println("Gelen Mesaj: ", msgserVer)
		input <- msgserVer
	}
}

func cliEnt(input <-chan string) {

	for {
		inputMessage := <-input
		fmt.Println("Message sent!...", inputMessage)
	}
}

func index(w http.ResponseWriter, r *http.Request) {

	message2Send := r.FormValue("message")

	d := struct {
		Message   string // Last  string
		MessageRX string
		MessageTX string
	}{
		Message:   message2Send, // Last:  lname,,
		MessageRX: Harici,
		MessageTX: message2Send,
	}
	err := temps.ExecuteTemplate(w, "index.templ", d)
	if err != nil {
		return
	}
	gidenMesajKanal <- message2Send

}

func wsroot(w http.ResponseWriter, r *http.Request) {

	fmt.Fprintf(w, "Hello WebSocket, message from fell: %s", Harici)

}

func main() {

	go serVer(gelenMesajKanal)

	go cliEnt(gidenMesajKanal)

	go func() { http.HandleFunc("/", index) }()

	go func() { http.HandleFunc("/ws", wsroot) }()

	go func() {

		err := http.ListenAndServe(":8888", nil)
		if err != nil {
			return
		}
	}()

	for {
		select {
		case <-gelenMesajKanal:
			Harici = <-gelenMesajKanal
			fmt.Printf("Calling server!...%v\n", <-gelenMesajKanal)
		}
	}
}
