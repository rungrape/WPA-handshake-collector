
class Logger:

    def __init__(self, log=None, err=None):
        '''
        log - информация
        errors - ошибки
        '''
        self.log, self.err =\
            Logger.checkParams(log, err)
        self.clean()

    @staticmethod
    def checkParams(log, err):
        if not (log and err):
            import platform
            if str(platform.system()) == 'Linux':
                log = log if log else '/tmp/log.txt'
                err = err if err else '/tmp/err.txt'
            elif str(platform.system()) == 'Windows':
                # TODO: find out which Win dirs are available to be written in
                log = log if log else '/tmp/log.txt'
                err = err if err else '/tmp/err.txt'
        return log, err

    def clean(self):
        '''
        очищаем файлы перед созданием новой сущности
        '''
        for _i in self.__dict__:
            with open(self.__dict__[_i], 'w', encoding='utf-8') as fw:
                fw.write('')

    def addLineToLog(self, line):
        '''
        (метод не обязательный, для отладки)
        регистрация события
        line - словарь с событием
        '''
        with open(self.log, 'a', encoding='utf-8') as fw:
            import datetime
            message = '--\n' + str(datetime.datetime.now()) + '\n'\
                    '\t1.Processing\n' +\
                    '\t\t' + line['function'] + '\n'\
                    '\t2.Output\n' +\
                    '\t\t' + line['output'] + '\n'
            fw.write(message)

    def addLineToErr(self, line):
        '''
        (метод не обязательный, для отладки)
        регистрация события
        line - словарь с событием
        '''
        with open(self.err, 'a', encoding='utf-8') as fw:
            import datetime
            message = '--\n' + str(datetime.datetime.now()) + '\n'\
                    '\t1.Processing\n' +\
                    '\t\t' + line['function'] + '\n'\
                    '\t2.Output\n' +\
                    '\t\t' + line['output'] + '\n'
            fw.write(message)

    def addToLine(self, function, output, level):
        '''
        (метод не обязательный, для отладки)
        создание события для вывода в лог
        function - где произошло
        output - что именно печатаем
        level - 'error' or 'log', logging level
        '''
        d = dict()
        d['function'] = function
        d['output'] = output
        if level == 'error':
            self.addLineToErr(d)
        elif level == 'log':
            self.addLineToLog(d)
