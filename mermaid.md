```mermaid

%%{
  init: {
    'theme': 'base',
    'themeVariables': {
      'xfontFamily':'helvetica,arial,times',
      'fontSize':'70px'
    }
  }
}%%
graph LR
    subgraph a
        subgraph a1
        end
        subgraph a2
        end
        subgraph a3
        end
    end
    subgraph b
        subgraph b1
        end
        subgraph b2
        end
        subgraph b3
        end
    end
    subgraph c
        subgraph c1
        end
        subgraph c2
        end
        subgraph c3
        end
    end
    a1~~~b1~~~c1
    a3~~~b3~~~c3
```
