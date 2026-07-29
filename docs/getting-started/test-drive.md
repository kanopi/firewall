# Test Drive

Follow these steps to quickly test Lite Firewall locally in a clean environment:

## 🧪 Quick Test Drive Setup

1. **Create a temporary folder**
   ```bash
   mkdir testdrive
   cd testdrive
   touch firewall.data
   ```

2. **Install Lite Firewall via Composer**
   ```bash
   composer require kanopi/firewall
   ```

3. **Create a basic `firewall.yml` configuration**

   ```yaml
    storage:
        type: "Kanopi\\Firewall\\Storage\\FileStorage"
        config:
            storage_file: firewall.data

    plugins:
        - plugin: "Kanopi\\Firewall\\Plugins\\Url"
          response: block
          enable: true
          config:
              - "query.block:1"   # Block any request that includes ?block=1
   ```

4. **Create an `index.php` file**

   ```php
   <?php
   require __DIR__ . '/vendor/autoload.php';

   use Kanopi\Firewall\Firewall;

   // Initialize firewall
   Firewall::create([__DIR__ . '/firewall.yml'])->evaluate();

   echo "Hello, world!";
   ```

5. **Start a PHP built-in web server**
   ```bash
   php -S localhost:8000
   ```

6. **Open your browser and test**

   - Visit [http://localhost:8000](http://localhost:8000) — you should see:
     ```
     Hello, world!
     ```

   - Visit [http://localhost:8000?block=1](http://localhost:8000?block=1) — you should see:
     ```
     Request Blocked
     ```

   - Visit [http://localhost:8000](http://localhost:8000) — you should see:
     ```
     Request Blocked
     ```

This simple example demonstrates how the firewall intercepts requests using YAML configuration and shows how easy it is to add rule-based blocking.

To start over empty the contents of the Storage file

```bash
echo "" > firewall.data
```
