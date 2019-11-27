# information
This challenge provided us the source code and the compiled binary file. We can compile it with the following command.
```
g++ prob.cpp -o outfile -std=c++11 -O2 -no-pie
```
The choice of `-O2` can be elimated to make debugg easier.
```
➜  Desktop file outfile 
outfile: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=09b8e94e90a9eaff10959e6d8a52730cb242d0bf, not stripped
➜  Desktop checksec outfile 
[*] '/home/osboxes/Desktop/outfile'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
# bug
The bug lies in this code snippest. It is obvious that there is a UAF of the variable *nowProcess*.
*allProcess* parameter will contain the *nowProcess* even if it was deleted.

The question is how to trigger this bug. The code implemented a script interpreter, input code will be parsed in two steps, *LAnalysis* and *Analysis*.

You can debug this challenge by adding `-g` argument in the compile command. Setting breakpoints in the source code, and press `c` to goto your breakpoint.
Like, if we want to debug the following code, we can set breakpoint with `break Analysis::StartAnalysis()`. Continue, and you will see it breaks on the function.
```CPP
            lastProcess = nowProcess;
            nowProcess = new Process(p->name, lastProcess->getLevel() + 1);
            allProcess.push_back(nowProcess);
            addVar(p->name, FUNCTION, 1);
            auto ret = S(_get_next(nnext));
            if(ret == _get_next(nnext))
            {
                delete(nowProcess);
                nowProcess = lastProcess;
                return nnext;
            }
            nowProcess = lastProcess;
            return ret;
```

# bug2
Also, when I was debugging this challenge, I found out that there is an uninitialize bug here in the class *Process*.
```CPP
class Process
{
  public:
    Process(string name, int level) : processName(name), level(level) 
    {
        vars = (Variable**)malloc(0x100);
        securt[0] = (char*)malloc(0x10);
        memcpy(securt[0],"d3ctf",6);
    }
    Process()
    {
        vars = (Variable**)malloc(0x100);
        securt[0] = (char*)malloc(0x10);
        memcpy(securt[0],"d3ctf",6);
    }
    void AddVar(Variable a)
    {
        if(position >= 0xe0/8)
        {
            return;
        }
        int n = position++;
        vars[n] = new Variable();
        *vars[n] = a;
    }
    bool HashVar(Variable a)
    {
        return false;
    }
    Variable** GetVar()
    {
        return this->vars;
    }
    int GetNum()
    {
        return this->position;
    }
    string GetName()
    {
        return processName;
    }

    int getLevel()
    {
        return this->level;
    }
    void ClearVar()
    {
        for(int i=0;i<position;i++)
        {
            delete(vars[i]);
            vars[i] = 0;
        }
        position = 0;
    }

    string Format(string padding)
    {
        if (GetName() == "main")
        {
            return "";
        }
        string res = padding + string(securt[0]) +  "Process";
        res += padding + + "\n";
        res += padding + "name : " + GetName() + "\n";
        res += padding + "type : function\n";
        res += padding + "plev : " + to_string(level) + "\n";
        return res;
    }

  private:
    char* securt[4] = {0};    
    Variable** vars;
    string processName;
    int level;
    int position;
};
```
Variable *position* was not intialized when a *Process* is created. So if it used an old chunk, there maybe some left value in it...

# leak
To make a leak, we just need 

# exploit

