#ifndef MQ_SERVER_H_
#define MQ_SERVER_H_
#include <proto/cpp/overlay.pb.h>
#include <common/general.h>
#include <common/pipeline_server.h>
#define  SEND_MAX_SIZE 1000
namespace bubi {

    class MQServer :public utils::Singleton<bubi::MQServer>, 
        public bubi::PipelineServer
	{
        friend class utils::Singleton<bubi::MQServer>;
    public:
        MQServer();
        ~MQServer();

		//重写send实现方法，加入队列,允许多线程访问
        virtual bool Send(const ZMQTaskType type, const std::string& buf);

		bool Initialize(MqServerConfigure & mq_server_configure);
        bool Exit();

        //Handlers
        static void OnChainHello(const char* msg, int len, std::string &reply);
        static void OnChainPeerMessage(const char* msg, int len, std::string &reply);
		static void OnSubmitTransaction(const char* msg, int len, std::string &reply);

	protected:
		virtual void OnTimer(int64_t current_time) override;
		virtual void OnSlowTimer(int64_t current_time) override;

	private:
		virtual void Recv(const ZMQTaskType type, std::string& buf);
		//因为mqserver中send涉及到多线程访问，因此加入消息队列来处理这一问题
		utils::ReadWriteLock send_list_mutex_;
		std::list<std::pair<ZMQTaskType, std::string>> send_list_;

		bool init_;
        
		static bool CheckCreateAccountOpe(const protocol::Operation &ope, Result &result);


		static bool CheckPayment(const protocol::Operation &ope, Result &result);

		static bool CheckIssueAsset(const protocol::Operation &ope, Result &result);

		static bool CheckSetOptions(const protocol::Operation &ope, Result &result);

		static bool CheckRecord(const protocol::Operation &ope, Result &result);
	};
}

#endif