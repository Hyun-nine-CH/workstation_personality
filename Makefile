CC      = gcc
CSTD    = -std=c11
# CFLAGS  = -O2 -Wall -pthread $(CSTD)
CFLAGS = -O2 -Wall -Wextra -Wshadow -pthread $(CSTD)

# 디렉토리
SRC_DIR    = src
INLINE_DIR = inline_hyungoo
COMMON_DIR = common_hyungoo
BIN_DIR    = bin

# include 경로
CFLAGS += -I$(SRC_DIR) -I$(COMMON_DIR) -I$(INLINE_DIR)

# 외부 라이브러리
PCAP_LIBS  = -lpcap
NFQ_CFLAGS = $(shell pkg-config --cflags libnetfilter_queue 2>/dev/null)
NFQ_LIBS   = $(shell pkg-config --libs   libnetfilter_queue 2>/dev/null)
ifeq ($(strip $(NFQ_LIBS)),)
	# NFQ_LIBS = -lnetfilter_queue -lmnl
	# Fallback: cover both libmnl(new) and libnfnetlink(old)
NFQ_LIBS = -lnetfilter_queue -lmnl -lnfnetlink
endif
RT_LIBS    = -lrt

# (옵션) post-accept 미러 마크 빌드 토글: make POST_ACCEPT=1
POST_ACCEPT ?= 0
ifeq ($(POST_ACCEPT),1)
  CFLAGS += -DUSE_POST_ACCEPT_MARK=1
endif

# SHM persist toggle (default 0 = flush)
PERSIST ?= 0

# ===== NFQueue runtime tuning =====
# if availably, Override such as make NFQ_QLEN=4096
NFQ_NUM ?= 0
NFQ_COPY ?= 1600
NFQ_QLEN ?= 8192
NFQ_RCVBUF_MB ?= 16

# ===== Analysis/Verdict engine tuning =====
# ENG_WORKERS ?= 2
# ENG_FANOUT ?= 0
# ENG_FLOW_CACHE ?= 0

# 실행파일
TARGET_IDS = $(BIN_DIR)/argus
TARGET_IPS = $(BIN_DIR)/argus_inline

# 소스
SRC_IDS = \
  $(SRC_DIR)/main.c \
  $(SRC_DIR)/thread_capture.c \
  $(SRC_DIR)/ts_packet_queue.c \
  $(SRC_DIR)/shm_consumer.c \
  $(SRC_DIR)/ids_log.c

SRC_IPS = \
  $(INLINE_DIR)/main_nfq.c \
  $(INLINE_DIR)/nfq_iface.c \
  $(INLINE_DIR)/packet_utils.c \
  $(INLINE_DIR)/ruleset.c

# 공용 모듈(양쪽 타깃 링크)
COMMON_SRCS = \
  $(COMMON_DIR)/ips_ring.c \
  $(COMMON_DIR)/shm_ipc.c

# 기본 타겟
all: $(TARGET_IDS) $(TARGET_IPS)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(TARGET_IDS): $(SRC_IDS) $(COMMON_SRCS) | $(BIN_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRC_IDS) $(COMMON_SRCS) $(PCAP_LIBS) $(RT_LIBS)

$(TARGET_IPS): $(SRC_IPS) $(COMMON_SRCS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(NFQ_CFLAGS) -o $@ $(SRC_IPS) $(COMMON_SRCS) $(NFQ_LIBS) $(RT_LIBS)

run_ids: $(TARGET_IDS)
	@echo "sudo $(TARGET_IDS)"
	@sudo $(TARGET_IDS)

run_ips: $(TARGET_IPS)
	@echo "sudo env ARGUS_SHM_PERSIST=$(PERSIST) $(TARGET_IPS)"
	@sudo env ARGUS_SHM_PERSIST=$(PERSIST) $(TARGET_IPS)

# tuning (forground)
run_ips_tuned: $(TARGET_IPS)
	@echo "sudo env ARGUS_SHM_PERSIST=$(PERSIST) ARGUS_NFQ_NUM=$(NFQ_NUM) ARGUS_NFQ_COPY=$(NFQ_COPY) ARGUS_NFQ_QLEN=$(NFQ_QLEN) ARGUS_NFQ_RCVBUF_MB=$(NFQ_RCVBUF_MB) $(TARGET_IPS)"
	@sudo env ARGUS_SHM_PERSIST=$(PERSIST) ARGUS_NFQ_NUM=$(NFQ_NUM) ARGUS_NFQ_COPY=$(NFQ_COPY) ARGUS_NFQ_QLEN=$(NFQ_QLEN) ARGUS_NFQ_RCVBUF_MB=$(NFQ_RCVBUF_MB) $(TARGET_IPS)

# tuning log/PID (background)
run_ips_bg: $(TARGET_IPS)
	@echo "nohup sudo env ARGUS_SHM_PERSIST=$(PERSIST) ARGUS_NFQ_NUM=$(NFQ_NUM) ARGUS_NFQ_COPY=$(NFQ_COPY) ARGUS_NFQ_QLEN=$(NFQ_QLEN) ARGUS_NFQ_RCVBUF_MB=$(NFQ_RCVBUF_MB) $(TARGET_IPS) > /tmp/argus_inline.out 2>&1 &"
	@nohup sudo env ARGUS_SHM_PERSIST=$(PERSIST) \
	         ARGUS_NFQ_NUM=$(NFQ_NUM) \
	         ARGUS_NFQ_COPY=$(NFQ_COPY) \
	         ARGUS_NFQ_QLEN=$(NFQ_QLEN) \
	         ARGUS_NFQ_RCVBUF_MB=$(NFQ_RCVBUF_MB) \
	         $(TARGET_IPS) > /tmp/argus_inline.out 2>&1 & echo $$! | tee /tmp/argus_inline.pid

# 원샷: flush 모드로 IPS BG + IDS FG
run_stack_flush_bg: PERSIST=0
run_stack_flush_bg: run_ips_bg run_ids

# 원샷: persist 모드로 IPS BG + IDS FG
run_stack_persist_bg: PERSIST=1
run_stack_persist_bg: run_ips_bg run_ids

# 백그라운드 IPS 종료
stop_ips_bg:
	-@[ -f /tmp/argus_inline.pid ] && sudo kill -TERM $$(cat /tmp/argus_inline.pid) && rm -f /tmp/argus_inline.pid || true
	-@sudo pkill -f "$(TARGET_IPS)" || true

# 전체 종료(백그라운드 IPS; IDS는 Ctrl+C)
stop_stack: stop_ips_bg
	@true

# setcap_inline: $(TARGET_IPS)
#	 sudo setcap cap_net_admin,cap_net_raw+ep $(TARGET_IPS)

# === managed ===
clean:
	rm -rf $(BIN_DIR)

rebuild: clean all

# === toggle ===
run_ips_persist: PERSIST=1
run_ips_persist: run_ips

run_ips_flush: PERSIST=0
run_ips_flush: run_ips

.PHONY: all clean rebuild run_ids run_ips run_ips_tuned run_ips_bg run_ips_persist run_ips_flush run_stack_flush_bg run_stack_persist_bg stop_ips_bg stop_stack
