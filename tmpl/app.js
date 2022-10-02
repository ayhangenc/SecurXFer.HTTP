window.onload = function() {

    // get the references of the page elements.
    var form = document.getElementById('form-msg');
    var txtMsg = document.getElementById('msg');
    var listMsgs = document.getElementById('msgs');
    var socketStatus = document.getElementById('status');
    var btnClose = document.getElementById('close');

    let socket = new WebSocket("ws://127.0.0.1:3000/v1/ws");
    console.log("Attempting Connection...");
    console.log("Walla, Attempting Connection...");

    socket.onopen = () => {
        console.log("Successfully Connected");
        socket.send("Hi From the Client!")
        socket.send(txtMsg)
    };

    socket.onclose = event => {
        console.log("Socket Closed Connection: ", event);
        socket.send("Client Closed!")
    };

    socket.onerror = error => {
        console.log("Socket Error: ", error);



        socket.addEventListener('message', (event) => {
            console.log('Message from server ', event.data);
        });


        while(socket.onmessage) {


        }
    };
};

