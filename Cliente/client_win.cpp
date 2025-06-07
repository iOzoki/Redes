#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>
#include <map>
#include <sstream>
#include <iomanip>
#include <conio.h>
#include <algorithm>

#pragma comment(lib, "Ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345
#define BUFFER_SIZE 4096

namespace Cliente {

// =================================================================================
// --- NAMESPACE MODEL ---
// =================================================================================
namespace Model {

    struct Contato {
        std::string username;
        bool online = false;
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
            char buffer[BUFFER_SIZE];
            std::string bufferRecepcao;
            while (conectado) {
                int bytesRecebidos = recv(sock, buffer, BUFFER_SIZE, 0);
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
                    std::cout << "\n[REDE] O servidor encerrou a conexao." << std::endl;
                    conectado = false;
                    break;
                }
            }
        }

    public:
        ClienteRede() : conectado(false) {}
        ~ClienteRede() { desconectar(); }

        bool conectar() {
            WSADATA wsaData;
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;

            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) return false;

            sockaddr_in serverAddr{};
            serverAddr.sin_family = AF_INET;
            serverAddr.sin_port = htons(SERVER_PORT);
            inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);

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

} // fim do namespace Model

// =================================================================================
// --- NAMESPACE VIEW ---
// =================================================================================
namespace View {

    class TerminalView {
    public:
        void limparTela() {
            system("cls");
        }

        void desenharCabecalho(const std::string& titulo) {
            std::cout << "================================================================" << std::endl;
            std::cout << " Cliente de Chat - " << titulo << std::endl;
            std::cout << "================================================================" << std::endl << std::endl;
        }

        void desenharTelaInicial() {
            limparTela();
            desenharCabecalho("Bem-vindo!");
            std::cout << "1. Login" << std::endl;
            std::cout << "2. Registrar" << std::endl;
            std::cout << "3. Sair" << std::endl;
            std::cout << "\nEscolha uma opcao: " << std::flush;
        }

        void aguardarServidor() {
            std::cout << "\nAguardando resposta do servidor..." << std::endl;
        }

        void exibirMensagemErro(const std::string& erro) {
            std::cout << "\n[ERRO] " << erro << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }

        void exibirMensagemSucesso(const std::string& sucesso) {
            std::cout << "\n[SUCESSO] " << sucesso << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }

        void desenharTelaChat(
            const std::string& usernameLogado,
            const std::string& chatAbertoCom,
            const std::map<std::string, Model::Contato>& contatos,
            const std::map<std::string, std::vector<Model::Mensagem>>& conversas,
            const std::string& inputAtual
        ) {
            limparTela();
            std::string titulo = "Chat - Logado como: " + usernameLogado;
            if (!chatAbertoCom.empty()) {
                titulo += " | Conversando com: " + chatAbertoCom;
            }
            desenharCabecalho(titulo);

            std::cout << "--- Contatos ---" << std::endl;
            int i = 1;
            std::vector<std::string> contatosOrdenados;
            for (auto const& [nome, contato] : contatos) {
                contatosOrdenados.push_back(nome);
            }
            std::sort(contatosOrdenados.begin(), contatosOrdenados.end());

            for (const auto& nome : contatosOrdenados) {
                auto contato = contatos.at(nome);
                std::cout << i++ << ". " << contato.username << " (" << (contato.online ? "Online" : "Offline") << ")" << std::endl;
            }
            std::cout << std::endl;
            std::cout << "Digite 'sair' para voltar a lista de contatos." << std::endl;
            std::cout << "Digite 'logout' para deslogar." << std::endl;

            std::cout << "\n--- Conversa ---" << std::endl;
            if (chatAbertoCom.empty()) {
                std::cout << "Nenhuma conversa selecionada." << std::endl;
                std::cout << "Digite 'chat [numero_do_contato]' para iniciar uma conversa." << std::endl;
            } else if (conversas.count(chatAbertoCom)) {
                for (const auto& msg : conversas.at(chatAbertoCom)) {
                    struct tm timeinfo;
                    localtime_s(&timeinfo, &msg.timestamp);
                    std::cout << "[" << std::put_time(&timeinfo, "%H:%M") << "] "
                              << msg.remetente << ": " << msg.conteudo << std::endl;
                }
            }

            std::cout << "\n----------------------------------------------------------------" << std::endl;
            std::cout << "> " << inputAtual << std::flush;
        }
    };

} // fim do namespace View

// =================================================================================
// --- NAMESPACE CONTROLLER ---
// =================================================================================
namespace Controller {

    class ChatController {
    private:
        enum class Estado { TELA_INICIAL, TELA_LOGIN, TELA_REGISTRO, TELA_CHAT, SAINDO };

        Estado estadoAtual = Estado::TELA_INICIAL;

        Model::ClienteRede rede;
        View::TerminalView view;

        std::string usernameLogado;
        std::string usernameTemporario;
        std::map<std::string, Model::Contato> contatos;
        std::map<std::string, std::vector<Model::Mensagem>> conversas;
        std::string chatAbertoCom = "";
        std::string inputAtual = "";
        bool precisaRedesenhar = true; // *** NOVA VARIÁVEL DE CONTROLE ***

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

        bool processarEntradaDeRede() {
            bool houveMudanca = false;
            while (rede.temMensagens()) {
                houveMudanca = true; // Uma mensagem chegou, a tela precisa ser redesenhada
                std::string msg = rede.getProximaMensagem();
                auto partes = parseString(msg, '|');
                if (partes.empty()) continue;

                const std::string& comando = partes[0];

                if (comando == "LOGIN_OK") {
                    mudarEstado(Estado::TELA_CHAT);
                    usernameLogado = usernameTemporario;
                    usernameTemporario.clear();
                    contatos.clear();
                    if (partes.size() > 1 && !partes[1].empty()) {
                        auto contatosStr = parseString(partes[1], ';');
                        for (const auto& cStr : contatosStr) {
                            auto detalhes = parseString(cStr, ',');
                            if (detalhes.size() == 2) {
                                contatos[detalhes[0]] = { detalhes[0], (detalhes[1] == "1") };
                            }
                        }
                    }
                } else if (comando == "LOGIN_FAIL") {
                    usernameTemporario.clear();
                    view.exibirMensagemErro(partes.size() > 1 ? partes[1] : "Falha no login.");
                    mudarEstado(Estado::TELA_INICIAL);
                } else if (comando == "REG_OK") {
                    view.exibirMensagemSucesso("Usuario registrado! Por favor, faca o login.");
                    mudarEstado(Estado::TELA_INICIAL);
                } else if (comando == "REG_FAIL") {
                    view.exibirMensagemErro(partes.size() > 1 ? partes[1] : "Falha no registro.");
                    mudarEstado(Estado::TELA_INICIAL);
                } else if (comando == "RECV_MSG") {
                    if (partes.size() < 4) continue;
                    std::string remetente = partes[1];
                    std::string conteudo = partes[2];
                    time_t timestamp = 0;
                    try { timestamp = std::stoll(partes[3]); } catch (...) {}
                    conversas[remetente].push_back({ remetente, conteudo, timestamp });
                } else if (comando == "USER_STATUS") {
                    if (partes.size() < 3) continue;
                    if(contatos.count(partes[1])) {
                        contatos[partes[1]].online = (partes[2] == "1");
                    }
                }
            }
            return houveMudanca;
        }

        bool processarEntradaDeUsuario() {
            if (_kbhit()) {
                char c = _getch();
                if (c == '\r') {
                    if (!inputAtual.empty()) {
                        if (chatAbertoCom.empty()) {
                            auto partes = parseString(inputAtual, ' ');
                            if (partes.size() == 2 && partes[0] == "chat") {
                                try {
                                    int index = std::stoi(partes[1]) - 1;
                                    std::vector<std::string> contatosOrdenados;
                                    for(auto const& [nome, val] : contatos) contatosOrdenados.push_back(nome);
                                    std::sort(contatosOrdenados.begin(), contatosOrdenados.end());
                                    if (index >= 0 && index < contatosOrdenados.size()) {
                                        chatAbertoCom = contatosOrdenados[index];
                                    }
                                } catch (...) {}
                            } else if (inputAtual == "logout") {
                                 rede.enviarMensagem("LOGOUT\n");
                                 mudarEstado(Estado::TELA_INICIAL);
                                 usernameLogado.clear();
                                 contatos.clear();
                                 conversas.clear();
                            }
                        } else {
                            if(inputAtual == "sair") {
                                chatAbertoCom.clear();
                            } else {
                                rede.enviarMensagem("MSG|" + chatAbertoCom + "|" + inputAtual + "\n");
                                conversas[chatAbertoCom].push_back({ usernameLogado, inputAtual, time(0) });
                            }
                        }
                        inputAtual.clear();
                    }
                } else if (c == '\b') {
                    if (!inputAtual.empty()) inputAtual.pop_back();
                } else {
                    inputAtual += c;
                }
                return true; // Houve mudança no input do usuário
            }
            return false;
        }

        void executarTelaLoginOuRegistro(bool isRegistro) {
            view.limparTela();
            view.desenharCabecalho(isRegistro ? "Registro de Novo Usuario" : "Login");

            std::string tempUser, tempPass;
            std::cout << "Digite o nome de usuario: ";
            std::getline(std::cin, tempUser);
            std::cout << "Digite a senha: ";
            std::getline(std::cin, tempPass);

            if (tempUser.empty() || tempPass.empty()) {
                view.exibirMensagemErro("Usuario e senha nao podem estar vazios.");
                mudarEstado(Estado::TELA_INICIAL);
                return;
            }

            if (isRegistro) {
                rede.enviarMensagem("REG|" + tempUser + "|" + tempPass + "\n");
            } else {
                usernameTemporario = tempUser;
                rede.enviarMensagem("LOGIN|" + tempUser + "|" + tempPass + "\n");
            }
            view.aguardarServidor();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // *** NOVA FUNÇÃO PARA MUDAR DE ESTADO E FORÇAR REDESENHO ***
        void mudarEstado(Estado novoEstado) {
            estadoAtual = novoEstado;
            precisaRedesenhar = true;
        }

    public:
        void executar() {
            if (!rede.conectar()) {
                std::cout << "Nao foi possivel iniciar o cliente. Pressione Enter para sair." << std::endl;
                std::cin.get();
                return;
            }

            while (estadoAtual != Estado::SAINDO && rede.estaConectado()) {
                // Processa eventos e verifica se algo mudou
                if (processarEntradaDeRede()) precisaRedesenhar = true;
                if (processarEntradaDeUsuario()) precisaRedesenhar = true;

                // Só redesenha a tela se algo tiver mudado
                if (precisaRedesenhar) {
                    switch (estadoAtual) {
                    case Estado::TELA_INICIAL:
                        view.desenharTelaInicial();
                        {
                            char escolha = '0';
                            std::cin >> escolha;
                            std::cin.ignore(10000, '\n');
                            if (escolha == '1') mudarEstado(Estado::TELA_LOGIN);
                            else if (escolha == '2') mudarEstado(Estado::TELA_REGISTRO);
                            else if (escolha == '3') mudarEstado(Estado::SAINDO);
                        }
                        break;
                    case Estado::TELA_LOGIN:
                        executarTelaLoginOuRegistro(false);
                        break;
                    case Estado::TELA_REGISTRO:
                        executarTelaLoginOuRegistro(true);
                        break;
                    case Estado::TELA_CHAT:
                        view.desenharTelaChat(usernameLogado, chatAbertoCom, contatos, conversas, inputAtual);
                        break;
                    case Estado::SAINDO:
                        break;
                    }
                    precisaRedesenhar = false; // Resetamos a flag após desenhar
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            rede.desconectar();
            std::cout << "\nPrograma encerrado." << std::endl;
        }
    };

} // fim do namespace Controller
} // fim do namespace Cliente

int main() {
    SetConsoleOutputCP(CP_UTF8);
    Cliente::Controller::ChatController app;
    app.executar();
    return 0;
}
