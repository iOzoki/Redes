#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <memory>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <chrono>

#include "imgui.h"

#define SERVER_IP_DEFAULT "127.0.0.1"
#define SERVER_PORT_DEFAULT 12345

namespace Cliente {

namespace Model {

    struct Contato {
        std::string username;
        bool online = false;
        bool estaDigitando = false;
    };

    struct Mensagem {
        std::string remetente;
        std::string conteudo;
        time_t timestamp;
    };

    class ClienteRede {
    private:
        SOCKET sock = INVALID_SOCKET;
        std::thread receiverThread;
        std::atomic<bool> conectado;
        std::vector<std::string> msgQueue;
        std::mutex queueMutex;

        void receberMensagens() {
            char buffer[4096];
            std::string bufferRecepcao;
            while (conectado) {
                int bytesRecebidos = recv(sock, buffer, 4096, 0);
                if (bytesRecebidos > 0) {
                    bufferRecepcao.append(buffer, bytesRecebidos);
                    size_t pos;
                    while ((pos = bufferRecepcao.find('\n')) != std::string::npos) {
                        std::string mensagemCompleta = bufferRecepcao.substr(0, pos);
                        bufferRecepcao.erase(0, pos + 1);
                        std::lock_guard<std::mutex> lock(queueMutex);
                        msgQueue.push_back(mensagemCompleta);
                    }
                } else {
                    conectado = false;
                    break;
                }
            }
        }

    public:
        ClienteRede() : conectado(false) {}
        ~ClienteRede() { desconectar(); }

        bool conectar(const std::string& ip, int porta) {
            if (conectado) return true;
            WSADATA wsaData;
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) return false;
            sockaddr_in serverAddr{};
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(porta);
            inet_pton(AF_INET, ip.c_str(), &serverAddr.sin_addr);
            if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
                closesocket(sock);
                sock = INVALID_SOCKET;
                return false;
            }
            conectado = true;
            receiverThread = std::thread(&ClienteRede::receberMensagens, this);
            return true;
        }

        void desconectar() {
            if (conectado.exchange(false)) {
                if (sock != INVALID_SOCKET) {
                    shutdown(sock, SD_BOTH);
                    closesocket(sock);
                    sock = INVALID_SOCKET;
                }
                if (receiverThread.joinable()) {
                    receiverThread.join();
                }
                WSACleanup();
            }
        }

        void enviarMensagem(const std::string& msg) {
            if (conectado) {
                send(sock, msg.c_str(), (int)msg.length(), 0);
            }
        }

        bool temMensagens() {
            std::lock_guard<std::mutex> lock(queueMutex);
            return !msgQueue.empty();
        }

        std::string getProximaMensagem() {
            std::lock_guard<std::mutex> lock(queueMutex);
            if (msgQueue.empty()) return "";
            std::string msg = msgQueue.front();
            msgQueue.erase(msgQueue.begin());
            return msg;
        }

        bool estaConectado() const {
            return conectado;
        }
    };

}

namespace Controller {

    class ChatController {
    private:
        enum class AppState { TELA_CONEXAO, TELA_LOGIN, TELA_REGISTRO, TELA_CHAT };

        AppState estadoAtual = AppState::TELA_CONEXAO;
        Model::ClienteRede rede;
        std::string usernameLogado;
        std::map<std::string, Model::Contato> contatos;
        std::map<std::string, std::vector<Model::Mensagem>> conversas;

        char ipServidor[64] = SERVER_IP_DEFAULT;
        int portaServidor = SERVER_PORT_DEFAULT;
        char usernameInput[128] = "";
        char passwordInput[128] = "";
        char mensagemInput[1024] = "";
        std::string statusMessage = "Por favor, conecte-se ao servidor.";
        std::string chatAbertoCom = "";
        float scrollParaBaixo = -1.0f;

        std::chrono::steady_clock::time_point ultimaTeclaPressionada;
        bool notificacaoDigitandoEnviada = false;

        std::vector<std::string> parseString(const std::string& str, char delim) {
            std::vector<std::string> tokens;
            if (str.empty()) return tokens;
            std::stringstream ss(str);
            std::string token;
            while (std::getline(ss, token, delim)) {
                tokens.push_back(token);
            }
            return tokens;
        }

        void processarEntradaDeRede() {
            while (rede.temMensagens()) {
                std::string msg = rede.getProximaMensagem();
                auto partes = parseString(msg, '|');
                if (partes.empty()) continue;
                const std::string& comando = partes[0];

                if (comando == "LOGIN_OK") {
                    estadoAtual = AppState::TELA_CHAT;
                    usernameLogado = usernameInput;
                    statusMessage = "Login bem-sucedido!";
                    contatos.clear();
                    if (partes.size() > 1 && !partes[1].empty()) {
                        auto contatosStr = parseString(partes[1], ';');
                        for (const auto& cStr : contatosStr) {
                            auto detalhes = parseString(cStr, ',');
                            if (detalhes.size() == 2) {
                                contatos[detalhes[0]] = { detalhes[0], (detalhes[1] == "1"), false };
                            }
                        }
                    }
                } else if (comando == "LOGIN_FAIL") {
                    statusMessage = "Falha no login: " + (partes.size() > 1 ? partes[1] : "Usuario ou senha invalidos.");
                } else if (comando == "REG_OK") {
                    statusMessage = "Usuario registrado com sucesso! Faca o login.";
                    estadoAtual = AppState::TELA_LOGIN;
                } else if (comando == "REG_FAIL") {
                    statusMessage = "Falha no registro: " + (partes.size() > 1 ? partes[1] : "Erro desconhecido.");
                } else if (comando == "RECV_MSG") {
                    if (partes.size() < 4) continue;
                    std::string remetente = partes[1];
                    std::string conteudo = partes[2];
                    time_t timestamp = 0;
                    try { timestamp = std::stoll(partes[3]); } catch (...) {}
                    std::string conversaKey = (remetente == usernameLogado) ? chatAbertoCom : remetente;
                    conversas[conversaKey].push_back({ remetente, conteudo, timestamp });
                    if (contatos.count(remetente)) {
                        contatos[remetente].estaDigitando = false;
                    }
                    scrollParaBaixo = ImGui::GetScrollMaxY() + 100.0f;
                } else if (comando == "USER_STATUS") {
                    if (partes.size() < 3) continue;
                    if (contatos.count(partes[1])) {
                        contatos[partes[1]].online = (partes[2] == "1");
                    }
                } else if (comando == "TYPING_ON_NOTIFY") {
                    if (partes.size() > 1 && contatos.count(partes[1])) {
                        contatos[partes[1]].estaDigitando = true;
                    }
                } else if (comando == "TYPING_OFF_NOTIFY") {
                     if (partes.size() > 1 && contatos.count(partes[1])) {
                        contatos[partes[1]].estaDigitando = false;
                    }
                }
            }
        }

        void DesenharTelaConexao() {
            ImGui::SetNextWindowPos(ImVec2(ImGui::GetIO().DisplaySize.x * 0.5f, ImGui::GetIO().DisplaySize.y * 0.5f), ImGuiCond_Always, ImVec2(0.5f,0.5f));
            ImGui::Begin("Conexao com o Servidor", NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize);
            ImGui::InputText("IP do Servidor", ipServidor, IM_ARRAYSIZE(ipServidor));
            ImGui::InputInt("Porta", &portaServidor);
            if (ImGui::Button("Conectar", ImVec2(120, 0))) {
                statusMessage = "Conectando...";
                if (rede.conectar(ipServidor, portaServidor)) {
                    estadoAtual = AppState::TELA_LOGIN;
                    statusMessage = "Conectado! Por favor, faca o login.";
                } else {
                    statusMessage = "Falha ao conectar ao servidor.";
                }
            }
            ImGui::Text("%s", statusMessage.c_str());
            ImGui::End();
        }

        void DesenharTelaLoginRegistro() {
            ImGui::SetNextWindowPos(ImVec2(ImGui::GetIO().DisplaySize.x * 0.5f, ImGui::GetIO().DisplaySize.y * 0.5f), ImGuiCond_Always, ImVec2(0.5f,0.5f));
            const char* titulo = (estadoAtual == AppState::TELA_LOGIN) ? "Login" : "Registro";
            ImGui::Begin(titulo, NULL, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize);
            ImGui::InputText("Usuario", usernameInput, IM_ARRAYSIZE(usernameInput));
            ImGui::InputText("Senha", passwordInput, IM_ARRAYSIZE(passwordInput), ImGuiInputTextFlags_Password);

            if (ImGui::Button(titulo, ImVec2(120, 0))) {
                std::string user(usernameInput);
                std::string pass(passwordInput);
                if (!user.empty() && !pass.empty()) {
                    std::string comando = (estadoAtual == AppState::TELA_LOGIN ? "LOGIN|" : "REG|");
                    rede.enviarMensagem(comando + user + "|" + pass + "\n");
                    statusMessage = "Aguardando resposta do servidor...";
                } else {
                    statusMessage = "Usuario e senha nao podem estar vazios.";
                }
            }
            ImGui::SameLine();
            if (ImGui::Button(estadoAtual == AppState::TELA_LOGIN ? "Ir para Registro" : "Ir para Login")) {
                estadoAtual = (estadoAtual == AppState::TELA_LOGIN ? AppState::TELA_REGISTRO : AppState::TELA_LOGIN);
                statusMessage = "";
            }
            ImGui::Text("%s", statusMessage.c_str());
            ImGui::End();
        }

        void DesenharTelaChat() {
            ImGui::Begin("Contatos", NULL, ImGuiWindowFlags_NoCollapse);
            if (ImGui::Button("Deslogar")) {
                rede.desconectar();
                estadoAtual = AppState::TELA_CONEXAO;
                usernameLogado.clear();
                contatos.clear();
                conversas.clear();
            }
            ImGui::Separator();
            for (auto& [nome, contato] : contatos) {
                ImVec4 corTexto = contato.online ? ImVec4(0.5f, 1.0f, 0.5f, 1.0f) : ImVec4(0.7f, 0.7f, 0.7f, 1.0f);
                ImGui::PushStyleColor(ImGuiCol_Text, corTexto);
                if (ImGui::Selectable(nome.c_str(), chatAbertoCom == nome)) {
                    chatAbertoCom = nome;
                }
                ImGui::PopStyleColor();
            }
            ImGui::End();

            ImGui::Begin("Conversa", NULL, ImGuiWindowFlags_NoCollapse);
            ImGui::Text("Conversando com: %s", chatAbertoCom.empty() ? "Ninguem" : chatAbertoCom.c_str());
            ImGui::Separator();

            ImGui::BeginChild("ScrollingRegion", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()), false, ImGuiWindowFlags_HorizontalScrollbar);
            if (!chatAbertoCom.empty()) {
                if (conversas.count(chatAbertoCom)) {
                    for (const auto& msg : conversas.at(chatAbertoCom)) {
                        struct tm timeinfo;
                        localtime_s(&timeinfo, &msg.timestamp);
                        std::stringstream ss;
                        ss << "[" << std::put_time(&timeinfo, "%H:%M") << "] " << msg.remetente << ": " << msg.conteudo;
                        ImGui::TextWrapped("%s", ss.str().c_str());
                    }
                }
                if (scrollParaBaixo >= 0.0f) {
                    ImGui::SetScrollY(scrollParaBaixo);
                    scrollParaBaixo = -1.0f;
                }

                if (contatos.count(chatAbertoCom) && contatos.at(chatAbertoCom).estaDigitando) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.7f, 0.7f, 1.0f));
                    ImGui::Text("%s está digitando...", chatAbertoCom.c_str());
                    ImGui::PopStyleColor();
                    ImGui::SetScrollY(ImGui::GetScrollMaxY());
                }
            }
            ImGui::EndChild();

            ImGui::Separator();

            auto agora = std::chrono::steady_clock::now();
            auto diff = std::chrono::duration_cast<std::chrono::seconds>(agora - ultimaTeclaPressionada).count();

            if (notificacaoDigitandoEnviada && diff > 2) {
                if (!chatAbertoCom.empty()) {
                    rede.enviarMensagem("TYPING_OFF|" + chatAbertoCom + "\n");
                }
                notificacaoDigitandoEnviada = false;
            }

            ImGui::PushItemWidth(-1);
            bool enterPressionado = ImGui::InputText("##mensagem", mensagemInput, IM_ARRAYSIZE(mensagemInput), ImGuiInputTextFlags_EnterReturnsTrue);
            ImGui::PopItemWidth();

            if (ImGui::IsItemActive() && ImGui::IsItemEdited()) {
                ultimaTeclaPressionada = std::chrono::steady_clock::now();
                if (!notificacaoDigitandoEnviada && !chatAbertoCom.empty()) {
                    rede.enviarMensagem("TYPING_ON|" + chatAbertoCom + "\n");
                    notificacaoDigitandoEnviada = true;
                }
            }

            if (enterPressionado) {
                if (strlen(mensagemInput) > 0 && !chatAbertoCom.empty()) {
                    if (notificacaoDigitandoEnviada) {
                        rede.enviarMensagem("TYPING_OFF|" + chatAbertoCom + "\n");
                        notificacaoDigitandoEnviada = false;
                    }

                    rede.enviarMensagem("MSG|" + chatAbertoCom + "|" + std::string(mensagemInput) + "\n");
                    conversas[chatAbertoCom].push_back({ usernameLogado, std::string(mensagemInput), time(0) });
                    scrollParaBaixo = ImGui::GetScrollMaxY() + 100.0f;
                    strcpy_s(mensagemInput, "");
                }
                ImGui::SetKeyboardFocusHere(-1);
            }
            ImGui::End();
        }

    public:
        ChatController() = default;

        ~ChatController() {
            if (rede.estaConectado()) {
                rede.enviarMensagem("LOGOUT\n");
                rede.desconectar();
            }
        }

        void ExecutarFrame() {
            if (!rede.estaConectado() && estadoAtual != AppState::TELA_CONEXAO) {
                 estadoAtual = AppState::TELA_CONEXAO;
                 statusMessage = "Desconectado do servidor. Tente conectar novamente.";
            }

            processarEntradaDeRede();

            switch(estadoAtual) {
                case AppState::TELA_CONEXAO:
                    DesenharTelaConexao();
                    break;
                case AppState::TELA_LOGIN:
                case AppState::TELA_REGISTRO:
                    DesenharTelaLoginRegistro();
                    break;
                case AppState::TELA_CHAT:
                    DesenharTelaChat();
                    break;
            }
        }
    };

}
}