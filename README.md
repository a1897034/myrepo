<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Websocket Test</title>
</head>
<body>
  <button onclick="contactServer">Click Here</button>
</body>
<script>
  const socket = new WebSocket('ws://localhost:13128');
socket.addEventListener('open', function(event) {
    socket.send("Connection Established");
});
socket.addEventListener('message', function(event) {
    console.log(event.data);
});
const contactServer = () => {
  socket.send("Hello World!");
}
</script>
</html
