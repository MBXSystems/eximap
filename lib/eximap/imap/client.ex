defmodule Eximap.Imap.Client do
  use GenServer
  alias Eximap.Imap.Request
  alias Eximap.Imap.Response
  alias Eximap.Socket

  require Logger

  @moduledoc """
  Imap Client GenServer
  """

  @initial_state %{socket: nil, tag_number: 1, conn_opts: nil}
  @literal ~r/{([0-9]*)}\r\n/s

  def start_link(opts \\ []) do
    case Keyword.get(opts, :name) do
      nil ->
        GenServer.start_link(__MODULE__, opts)

      name ->
        GenServer.start_link(__MODULE__, opts, name: name)
    end
  end

  def init(opts) do
    conn_opts = %{
      host: Keyword.get(opts, :host) |> to_charlist(),
      port: Keyword.get(opts, :port),
      account: Keyword.get(opts, :account),
      password: Keyword.get(opts, :password),
      socket_options: Keyword.get(opts, :socket_options, []) |> build_opts()
    }

    {:ok, %{@initial_state | conn_opts: conn_opts}}
  end

  def connect(pid) do
    pid
    |> GenServer.call(:connect)
    |> compose_response()
  end

  def execute(pid, req) do
    pid
    |> GenServer.call({:command, req})
    |> compose_response()
  end

  def handle_call(
        :connect,
        _from,
        %{
          conn_opts: %{
            host: host,
            port: port,
            account: account,
            password: password,
            socket_options: sock_opts
          }
        } = state
      ) do
    case Socket.connect(true, host, port, sock_opts) do
      {:error, _} = err ->
        {:reply, err, state}

      {:ok, socket} ->
        # todo: parse the server attributes and store them in the state
        msg = imap_receive_raw(socket)
        Logger.debug(fn -> "#{inspect msg}" end)

        req = Request.login(account, password) |> Request.add_tag("EX_LGN")
        # Do log login request, as it includes the password
        resp = imap_send(socket, req, false)
        {:reply, resp, %{state | socket: socket}}
    end
  end

  def handle_call(
        {:command, %Request{} = req},
        _from,
        %{socket: socket, tag_number: tag_number} = state
      ) do
    resp = imap_send(socket, %Request{req | tag: "EX#{tag_number}"})
    {:reply, resp, %{state | tag_number: tag_number + 1}}
  end

  def handle_info(_resp, state) do
    {:noreply, state}
  end

  #
  # Private methods
  #
  defp compose_response(%Response{status: "OK"} = resp), do: {:ok, resp}
  defp compose_response(%Response{status: _} = resp), do: {:error, resp}
  defp compose_response(resp), do: resp

  defp build_opts(user_opts) do
    allowed_opts =
      user_opts |> Enum.reject(fn {k, _} -> k == :binary || k == :active end)

    [:binary, active: false] ++ allowed_opts
  end

  defp imap_send(socket, req, log \\ true) do
    message = Request.raw(req)
    imap_send_raw(socket, message, log)
    imap_receive(socket, req)
  end

  defp imap_send_raw(socket, msg, true = _log) do
    Logger.debug(fn -> "#{inspect msg}" end)
    imap_send_raw(socket, msg, false)
  end

  defp imap_send_raw(socket, msg, false = _log) do
    Socket.send(socket, msg)
  end

  defp imap_receive(socket, req) do
    msg = assemble_msg(socket, req.tag)
    Logger.debug(fn -> "#{inspect msg}" end)
    %Response{request: req} |> parse_message(msg)
  end

  # assemble a complete message
  defp assemble_msg(socket, tag), do: assemble_msg(socket, tag, "")

  defp assemble_msg(socket, tag, msg) do
    {:ok, recv} = Socket.recv(socket, 0)
    msg = msg <> recv

    if Regex.match?(~r/^.*#{tag} .*\r\n$/s, msg),
      do: msg,
      else: assemble_msg(socket, tag, msg)
  end

  defp parse_message(resp, ""), do: resp

  defp parse_message(resp, msg) do
    [part, other_parts] = get_msg_part(msg)
    {:ok, resp, other_parts} = Response.parse(resp, part, other_parts)
    if resp.partial, do: parse_message(resp, other_parts), else: resp
  end

  # get [message part, other message parts] that recognises {size}\r\n literals
  defp get_msg_part(msg), do: get_msg_part("", msg)

  defp get_msg_part(part, other_parts) do
    if other_parts =~ @literal do
      [_match | [size]] = Regex.run(@literal, other_parts)
      size = String.to_integer(size)
      [head, tail] = String.split(other_parts, @literal, parts: 2)
      # literal = for i <- 0..(size - 1), do: Enum.at(String.codepoints(tail), i)
      # Performace boost.  Large messages and attachments killed this and took > 2 minutes for a 40K attachment.
      cp = String.codepoints(tail)
      {literal, _post_literal_cp} = Enum.split(cp, size)
      literal = to_string(literal)
      {_, post_literal} = String.split_at(tail, String.length(literal))

      case post_literal do
        "\r\n" <> next -> [part <> head <> literal, next]
        _ -> get_msg_part(part <> head <> literal, post_literal)
      end
    else
      [h, t] = String.split(other_parts, "\r\n", parts: 2)
      [part <> h, t]
    end
  end

  defp imap_receive_raw(socket) do
    {:ok, msg} = Socket.recv(socket, 0)
    msgs = String.split(msg, "\r\n", parts: 2)
    msgs = Enum.drop(msgs, -1)
    #    Enum.map(msgs, &(IO.inspect "S: #{&1}"))
    msgs
  end
end
