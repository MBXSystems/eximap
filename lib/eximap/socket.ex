defmodule Eximap.Socket do
  @moduledoc """
  A socket module that abstracts away the type of the connection it has with a server.
  """

  @doc """
  Connect to a node using either :ssl or :gen_tcp
  """
  def connect(false, host, port, opts), do: :gen_tcp.connect(host, port, opts)

  def connect(true = _usessl, host, port, opts) do
    :ssl.start()
    :ssl.connect(host, port, opts)
  end

  @doc """
  Set options for the socket based on the type of the connection
  """
  def setopts(socket, opts) do
    socket
    |> elem(0)
    |> case do
      :sslsocket -> :ssl.setopts(socket, opts)
      :gen_tcp -> :inet.setopts(socket, opts)
    end
  end

  @doc """
  Send some data to the socket abstracting the type of the socket away
  """
  def send(socket, msg) do
    socket
    |> elem(0)
    |> case do
      :sslsocket -> :ssl.send(socket, msg)
      :gen_tcp -> :gen_tcp.send(socket, msg)
    end
  end

  @doc """
  Receive data from the socket
  """
  def recv(socket, length) do
    socket
    |> elem(0)
    |> case do
      :sslsocket -> :ssl.recv(socket, length)
      :gen_tcp -> :gen_tcp.recv(socket, length)
    end
  end

  def recv(socket, length, timeout) do
    socket
    |> elem(0)
    |> case do
      :sslsocket -> :ssl.recv(socket, length, timeout)
      :gen_tcp -> :gen_tcp.recv(socket, length, timeout)
    end
  end
end
