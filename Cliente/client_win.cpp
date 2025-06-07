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
#include <iomanip> // Para formatação de tempo
#include <conio.h> // Para _kbhit e _getch (leitura de teclado não bloqueante)

#pragma comment(lib, "Ws2_32.lib")

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345
#define BUFFER_SIZE 4096

// =================================================================================
// --- ESTRUTURAS DE DADOS DO CLIENTE ---
// =================================================================================

struct Contato {
    std::string username;
    bool online = false;
};

struct Mensagem {
    std::string remetente;
    std::string conteudo;
    time_t timestamp;
};

// =================================================================================
// --- CLASSE DE REDE ---
// =================================================================================

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
            }
            else {
                // Erro ou desconexão
                std::cout << "[REDE] Servidor desconectado." << std::endl;
                conectado = false;
                break;
            }
        }
    }

public:
    ClienteRede() : conectado(false) {}

    ~ClienteRede() {
        desconectar();
    }

    bool conectar() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            std::cerr << "WSAStartup falhou." << std::endl;
            return false;
        }

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            std::cerr << "Criacao do socket falhou." << std::endl;
            return false;
        }

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(SERVER_PORT);
        inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);

        if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            std::cerr << "Nao foi possivel conectar ao servidor." << std::endl;
            closesocket(sock);
            sock = INVALID_SOCKET;
            return false;
        }

        conectado = true;
        receiverThread = std::thread(&ClienteRede::receberMensagens, this);
        return true;
    }

    void desconectar() {
        if (conectado) {
            conectado = false;
            closesocket(sock);
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
        if (msgQueue.empty()) {
            return "";
        }
        std::string msg = msgQueue.front();
        msgQueue.erase(msgQueue.begin());
        return msg;
    }
};

// =================================================================================
// --- APLICAÇÃO PRINCIPAL DO CLIENTE ---
// =================================================================================

class ChatCliente {
private:
    enum class Estado { TELA_INICIAL, TELA_LOGIN, TELA_REGISTRO, TELA_CHAT };

    Estado estadoAtual = Estado::TELA_INICIAL;
    ClienteRede rede;
    std::string usernameLogado;
    std::map<std::string, Contato> contatos;
    std::map<std::string, std::vector<Mensagem>> conversas;
    std::string chatAbertoCom = "";
    std::string inputAtual = "";

    // --- Funções de Desenho da UI no Console ---
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

    void desenharTelaLoginOuRegistro(bool isRegistro) {
        limparTela();
        desenharCabecalho(isRegistro ? "Registro de Novo Usuario" : "Login");
        std::string promptUsuario = "Digite o nome de usuario: ";
        std::string promptSenha = "Digite a senha: ";

        std::string tempUser, tempPass;

        std::cout << promptUsuario;
        std::getline(std::cin, tempUser);

        std::cout << promptSenha;
        std::getline(std::cin, tempPass);

        if (isRegistro) {
            std::string msg = "REG|" + tempUser + "|" + tempPass + "\n";
            rede.enviarMensagem(msg);
        }
        else {
            std::string msg = "LOGIN|" + tempUser + "|" + tempPass + "\n";
            rede.enviarMensagem(msg);
        }
        std::cout << "\nAguardando resposta do servidor..." << std::endl;
    }

    void desenharTelaChat() {
        limparTela();
        std::string titulo = "Chat - Logado como: " + usernameLogado;
        if (!chatAbertoCom.empty()) {
            titulo += " | Conversando com: " + chatAbertoCom;
        }
        desenharCabecalho(titulo);

        // Lado Esquerdo: Contatos
        std::cout << "--- Contatos ---" << std::endl;
        int i = 1;
        std::vector<std::string> contatosOrdenados;
        for (auto const& [nome, contato] : contatos) {
            contatosOrdenados.push_back(nome);
        }
        std::sort(contatosOrdenados.begin(), contatosOrdenados.end());

        for (const auto& nome : contatosOrdenados) {
            auto contato = contatos[nome];
            std::cout << i++ << ". " << contato.username << " (" << (contato.online ? "Online" : "Offline") << ")" << std::endl;
        }
        std::cout << std::endl;

        // Lado Direito: Conversa
        std::cout << "--- Conversa ---" << std::endl;
        if (chatAbertoCom.empty()) {
            std::cout << "Nenhuma conversa selecionada." << std::endl;
            std::cout << "Digite 'chat [numero_do_contato]' para iniciar uma conversa." << std::endl;
        }
        else {
            for (const auto& msg : conversas[chatAbertoCom]) {
                struct tm timeinfo;
                localtime_s(&timeinfo, &msg.timestamp);
                std::cout << "[" << std::put_time(&timeinfo, "%H:%M") << "] "
                    << msg.remetente << ": " << msg.conteudo << std::endl;
            }
        }

        // Rodapé: Input do usuário
        std::cout << "\n----------------------------------------------------------------" << std::endl;
        std::cout << "> " << inputAtual << std::flush;
    }

    // --- Funções de Processamento de Lógica ---
    std::vector<std::string> parseString(const std::string& str, char delim) {
        std::vector<std::string> tokens;
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
                estadoAtual = Estado::TELA_CHAT;
                usernameLogado = parseString(params[1],"|")[0];
                // Processa a lista de contatos
                auto contatosStr = parseString(partes[1], ';');
                for (const auto& cStr : contatosStr) {
                    auto detalhes = parseString(cStr, ',');
                    if (detalhes.size() == 2) {
                        contatos[detalhes[0]] = { detalhes[0], (detalhes[1] == "1") };
                    }
                }
            }
            else if (comando == "LOGIN_FAIL") {
                std::cout << "\n[ERRO] " << partes[1] << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(2));
                estadoAtual = Estado::TELA_INICIAL;
            }
            else if (comando == "REG_OK") {
                std::cout << "\n[SUCESSO] Usuario registrado! Por favor, faca o login." << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(2));
                estadoAtual = Estado::TELA_INICIAL;
            }
            else if (comando == "REG_FAIL") {
                 std::cout << "\n[ERRO] " << partes[1] << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(2));
                estadoAtual = Estado::TELA_INICIAL;
            }
            else if (comando == "RECV_MSG") {
                if (partes.size() < 4) continue;
                std::string remetente = partes[1];
                std::string conteudo = partes[2];
                time_t timestamp = std::stoll(partes[3]);
                conversas[remetente].push_back({ remetente, conteudo, timestamp });
            }
            else if (comando == "USER_STATUS") {
                if (partes.size() < 3) continue;
                if(contatos.count(partes[1])) {
                    contatos[partes[1]].online = (partes[2] == "1");
                }
            }
        }
    }

    void processarEntradaDeUsuario() {
        if (_kbhit()) {
            char c = _getch();
            if (c == '\r') { // Enter
                if (!inputAtual.empty()) {
                    if (chatAbertoCom.empty()) { // Comandos globais
                        auto partes = parseString(inputAtual, ' ');
                        if (partes.size() == 2 && partes[0] == "chat") {
                            int index = std::stoi(partes[1]) - 1;
                            std::vector<std::string> contatosOrdenados;
                            for(auto const& [nome, val] : contatos) contatosOrdenados.push_back(nome);
                            std::sort(contatosOrdenados.begin(), contatosOrdenados.end());
                            if (index >= 0 && index < contatosOrdenados.size()) {
                                chatAbertoCom = contatosOrdenados[index];
                            }
                        }
                    }
                    else { // Enviando mensagem
                        std::string msg = "MSG|" + chatAbertoCom + "|" + inputAtual + "\n";
                        rede.enviarMensagem(msg);
                        conversas[chatAbertoCom].push_back({ usernameLogado, inputAtual, time(0) });
                    }
                    inputAtual.clear();
                }
            }
            else if (c == '\b') { // Backspace
                if (!inputAtual.empty()) {
                    inputAtual.pop_back();
                }
            }
            else {
                inputAtual += c;
            }
        }
    }


public:
    void executar() {
        if (!rede.conectar()) {
            std::cout << "Nao foi possivel iniciar o cliente. Pressione Enter para sair." << std::endl;
            std::cin.get();
            return;
        }

        while (estadoAtual != Estado::SAINDO) {
            switch (estadoAtual) {
            case Estado::TELA_INICIAL:
                desenharTelaInicial();
                {
                    char escolha;
                    std::cin >> escolha;
                    std::cin.ignore(); // Limpa o buffer do newline
                    if (escolha == '1') estadoAtual = Estado::TELA_LOGIN;
                    else if (escolha == '2') estadoAtual = Estado::TELA_REGISTRO;
                    else if (escolha == '3') estadoAtual = Estado::SAINDO;
                }
                break;
            case Estado::TELA_LOGIN:
                desenharTelaLoginOuRegistro(false);
                std::this_thread::sleep_for(std::chrono::seconds(1)); // Espera a rede
                break;
            case Estado::TELA_REGISTRO:
                desenharTelaLoginOuRegistro(true);
                std::this_thread::sleep_for(std::chrono::seconds(1)); // Espera a rede
                break;
            case Estado::TELA_CHAT:
                processarEntradaDeUsuario();
                desenharTelaChat();
                break;
            }
            processarEntradaDeRede();
            std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Pequena pausa para não sobrecarregar a CPU
        }
        rede.desconectar();
    }
};


int main() {
    SetConsoleOutputCP(CP_UTF8);
    ChatCliente cliente;
    cliente.executar();
    return 0;
}
