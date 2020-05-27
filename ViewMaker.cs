using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WindowsSniffer
{
    class ViewMaker
    {
        private const int FLAG = 6;
        private const int PROTOCOL_IPv4 = 9;
        private const int ICMP_TYPE = 13;
        private const int ICMP_CODE = 14;
        private const int TCP_FLAG = 5;
        private const int TCP_FLAG_ALL = 5 + 13;

        private readonly string[] IPv4SimplArr = { "IPv", " ДлЗагол:", " DSCP:", " ECN:",
            " ОбщДлин: ", " Идент: ", " Фл: ", " Отст: ", " TTL: ", " Протокол: ", " Сумма:",
            "IP ист: ", "IP назн: "
        };



        private readonly string[] IPv4ExtendArrDescribe = {
            "Версия протокола IP", 
            "Поскольку число опций не постоянно, указание размера важно для отделения заголовка от данных.",
            "Используется для разделения трафика на классы обслуживания", 
            "Предупреждение о перегрузке сети без потери пакетов.",
            "Общая длина заголовка и пакета", 
            "Преимущественно используется для идентификации фрагментов пакета, если он был фрагментирован.",
            "Поле размером три бита содержащее флаги контроля над фрагментацией.",
            "Смещение фрагмента",
            "Время жизни. максимальное количество маршрутизаторов на пути следования пакета.", 
            "Указывает, данные какого протокола IP содержит пакет",
            "16-битная контрольная сумма, используемая для проверки целостности заголовка.",
            "32-битный адрес отправителя пакета.",
            "32-битный адрес получателя пакета."
        };

        public readonly string[] IPv4ExtendHeader =
        {
            "Протокол IPv",
            "Длина заголовка",
            "«Differentiated Services»",
            "ECN",
            "Общая длина",
            "Идентификатор",
            "Флаги",
            "Смещение фрагмента",
            "TTL",
            "Протокол",
            "Сумма",
            "Отправитель",
            "Получатель"
        };

        private readonly string[] IPv6SimplArr = { "IPv", " Приор:", " Метка:", " Размер:",
            " След: ", " HopLim: ", "IP ист: ", "IP назн: "
        };

        private readonly string[] IPv6ExtHeader =
        {
            "Version",
            "Traffic Class",
            "Flow Label",
            "Payload Length",
            "Next Header",
            "Hop Limit",
            "Source Address",
            "Destination Address"

        };

        private readonly string[] IPv6Describe =
        {
            "версия протокола",
            "приоритет пакета",
            "метка потока",
            "размер данных, не включая данный заголовок, но включая все расширенные заголовки",
            "задаёт тип расширенного заголовка",
            "аналог поля time to live в IPv4",
            "адрес отправителя",
            "адрес получателя"
        };


        private readonly string[] fICMPHeaders = { 
            "[ICMP] Тип",
            "[ICMP] Код",
            "[ICMP] Контрольная сумма",
            "[ICMP] Данные заголовка",
            "[ICMP] Данные" };

        private readonly string[] fICMPDescribe =
        {
            "",
            "",
            "Проверки корректности данных. Рассчитанна из заголовка ICMP и данных(для этого поля значение = 0).",
            "Дополнительные данные заголовка (в настоящее время только для контрольной суммы)",
            "Заголовок и первые 64 бита данных"
        };

        private readonly string[] FICMPCodes3 =
        {
            "Сеть недоступна.",
            "Хост недоступен.",
            "Протокол недоступен.",
            "Порт недоступен.",
            "Необходима фрагментация и набор DF.",
            "Исходный маршрут не удался."

        };

        private readonly string[] FICMPCodes11 =
        {
            "Время жизни превышено в пути.",
            "Превышено время сборки фрагмента."
        };

        private readonly string[] FICMPCodes12 =
        {
            "Указывает на ошибку."
        };

        private readonly string[] FICMPCodes5 =
        {
            "Перенаправление дейтаграмм для Сети.",
            "Перенаправление дейтаграмм для хоста.",
            "Перенаправление дейтаграмм для типа сервиса и сети.",
            "Перенаправление дейтаграмм для типа сервиса и хоста."
        };

        private readonly string[] fTCPHeaders =
        {
            "[TCP] Порт источника",
            "[TCP] Порт назначения",
            "[TCP] Порядковый номер",
            "[TCP] Номер подтверждения",
            "[TCP] Длина заголовка",
            "[TCP] Флаги",
            "[TCP] Размер окна",
            "[TCP] Контрольная сумма",
            "[TCP] Указатель важности",
            "[TCP] Опции",
            "[TCP] Данные"

        };

        private readonly string[] fTCPDescribe =
        {
            "Порт источника идентифицирует приложение клиента, с которого отправлены пакеты",
            "Порт назначения идентифицирует порт, на который отправлен пакет.",
            "Если установлен флаг SYN (идёт установление сессии)," +
                " то поле содержит изначальный порядковый номер — ISN. В противном случае," +
                " первый байт данных, передаваемый в данном пакете, имеет этот порядковый номер.",
            "Если установлен флаг ACK, то это поле содержит порядковый номер октета," +
                " который отправитель данного сегмента желает получить.",
            "Длина заголовка (Data offset) занимает 4 бита и указывает значение длины заголовка.",
            "",
            "Определяет количество байт данных (payload), " +
                "после передачи которых отправитель ожидает подтверждения от получателя, что данные получены.",
            "16-битное дополнение к сумме всех 16-битных слов заголовка (включая псевдозаголовок) и данных",
            "Указывает порядковый номер октета, которым заканчиваются важные (urgent) данные." +
                " Поле принимается во внимание только для пакетов с установленным флагом URG.",
            "Могут применяться в некоторых случаях для расширения протокола.",
            "Данные пакета"

        };

        private readonly string[] TCPFlagDescrib =
        {
            "URG — поле «Указатель важности» задействовано",
            "ACK — поле «Номер подтверждения» задействовано",
            "PSH — инструктирует получателя протолкнуть данные, накопившиеся в приёмном буфере, в приложение пользователя",
            "RST — оборвать соединения, сбросить буфер",
            "SYN — синхронизация номеров последовательности",
            "FIN — указывает на завершение соединения"
        };

        private readonly string[] fUDPHeaders =
        {
            "[UDP] Порт отправителя",
            "[UDP] Порт получателя",
            "[UDP] Длина датаграммы",
            "[UDP] Контрольная сумма",
            "[UDP] Данные"

        };

        private readonly string[] fUDPDescribe =
        {
            "Номер порта отправителя. " +
                "Предполагается, что это значение задаёт порт, на который при необходимости будет посылаться ответ.",
            "Аналогично порту отправителя, если хостом-получателем является клиент," +
                " то номер порта динамический, если получатель — сервер, то это будет «хорошо известный» порт",
            "Поле, задающее длину всей датаграммы (заголовка и данных) в байтах.",
            "Используется для проверки заголовка и данных на ошибки.",
            "Данные пакета"

        };

        private string GetFlagDescribe(string flag)
        {
            byte bFlag = Byte.Parse(flag);
            string startDecript = " Флаги " + Convert.ToString(bFlag, 2) + " означают ";
            if ((bFlag & 0b010) != 0)
            {
                return startDecript + "не фрагментировать";
            }else if ((bFlag & 0b100) != 0)
            {
                return startDecript + "у пакета ещё есть фрагменты";
            }
            else
            {
                return startDecript + "последний фрагмент";
            }
        }

        private string[] GetCodeAndTypeICMP(string type, string code)
        {
            string[] result = new string[2];
            int iCode = int.Parse(code);
            result[1] = "Код сообщения";
            switch (type)
            {
                case "0": 
                    result[0] = "Эхо-Ответ"; 
                    break;
                case "3": result[0] = "Пункт назначения недоступен";
                    if (iCode < FICMPCodes3.Length)
                        result[1] = FICMPCodes3[iCode];
                    break;
                case "4":
                    result[0] = "Сдерживание источника";
                    break;
                case "5":
                    result[0] = "Перенаправление";
                    if (iCode < FICMPCodes5.Length)
                        result[1] = FICMPCodes5[iCode];
                    break;
                case "8":
                    result[0] = "Эхо";
                    break;
                case "11":
                    result[0] = "Превышено время";
                    if (iCode < FICMPCodes11.Length)
                        result[1] = FICMPCodes11[iCode];
                    break;
                case "12":
                    result[0] = "Неверные параметры";
                    if (iCode < FICMPCodes12.Length)
                        result[1] = FICMPCodes12[iCode];
                    break;
                case "13":
                    result[0] = "Отметка времени"; 
                    break;
                case "14":
                    result[0] = "Отметка времени: Ответ"; 
                    break;
                case "15":
                    result[0] = "Запрос информации"; 
                    break;
                case "16":
                    result[0] = "Ответ на запрос информации"; 
                    break;
                default:
                    result[0] = "Неизвестно";
                    break;
            }
            return result;
        }

        private string AnalizeTCPFlags(string flags)
        {
            int iFlags = int.Parse(flags);
            string flagDescription = "";
            int mask = 0b100000;
            for (int i = 0; i < TCPFlagDescrib.Length; i++)
            {
                if ((mask & iFlags) != 0)
                {
                    flagDescription += TCPFlagDescrib[i];
                }
                mask >>= 1;
            }
            return flagDescription;
            
        }

        private List<string>[] AddSubProtocolDescribe(List<string>[] baseArr, List<string> packet)
        {
            var protocol = packet[PROTOCOL_IPv4];
            switch (protocol)
            {
                case "ICMP":
                    string[] tmpICMPDescribe = fICMPDescribe;
                    var tmpCodeAndType = GetCodeAndTypeICMP(packet[ICMP_TYPE], packet[ICMP_CODE]);
                    tmpICMPDescribe[0] = tmpCodeAndType[0];
                    tmpICMPDescribe[1] = tmpCodeAndType[1];
                    baseArr[0].AddRange(fICMPHeaders);
                    baseArr[1].AddRange(tmpICMPDescribe);
                    break;
                case "UDP":
                    baseArr[0].AddRange(fUDPHeaders);
                    baseArr[1].AddRange(fUDPDescribe);
                    break;
                case "TCP":
                    string[] tmpTCPDescribe = fTCPDescribe;
                    tmpTCPDescribe[TCP_FLAG] = AnalizeTCPFlags(packet[TCP_FLAG_ALL]);
                    baseArr[0].AddRange(fTCPHeaders);
                    baseArr[1].AddRange(tmpTCPDescribe);
                    break;
            }
            return baseArr;
        }

        private List<string>[] MakeExtendListIPv4(List<string> packet)
        {
            string[] describeArr = IPv4ExtendArrDescribe;
            describeArr[FLAG] = GetFlagDescribe(packet.ElementAt(FLAG));
            List<string>[] arrLists = new List<string>[2];
            arrLists[0] = new List<string>(IPv4ExtendHeader);
            arrLists[1] = new List<string>(describeArr);
            arrLists = AddSubProtocolDescribe(arrLists, packet);
            return arrLists;

        }

        private List<string>[] MakeExtendListIPv6(List<string> packet)
        {
            List<string>[] arrLists = new List<string>[2];
            arrLists[0] = new List<string>(IPv6ExtHeader);
            arrLists[1] = new List<string>(IPv6Describe);
            return arrLists;

        }

        public List<string>[] MakeExtendList(List<string> packetInf)
        {
            switch (packetInf.ElementAt(0))
            {
                case "4":
                    return MakeExtendListIPv4(packetInf);
                case "6":
                    return MakeExtendListIPv6(packetInf);

            }
            return null;
        }



        private string MakeSimpleIPv4(List<string> packetInf)
        {
            string info = "";
            for (int i = 0; i < IPv4SimplArr.Length; i++)
            {
                info += IPv4SimplArr[i] + packetInf.ElementAt(i);
            }
            return info;
        }


        private string MakeSimpleIPv6(List<string> packetInf)
        {
            string info = "";
            for (int i = 0; i < IPv6SimplArr.Length; i++)
            {
                info += IPv6SimplArr[i] + packetInf.ElementAt(i);
            }
            return info;
        }


        public string MakeSimple(List<string> packetInf)
        {
            switch (packetInf.ElementAt(0))
            {
                case "4":
                    return MakeSimpleIPv4(packetInf);
                case "6":
                    return MakeSimpleIPv6(packetInf);

            }
            return null;
        }
    }
}
