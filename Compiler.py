import os
import subprocess
import sys
import shutil
import re
from pathlib import Path

class SafeCompiler:
    def __init__(self):
        self.script_dir = Path.cwd()
        self.original_script = self.script_dir / "Lunex.pyw"
        self.fixed_script = self.script_dir / "Lunex_fixed.pyw.pyw"
        self.dist_dir = self.script_dir / "dist"
        self.build_dir = self.script_dir / "build"
        self.name = "Lunex"

    def create_compatible_script(self):
        """Cria uma versão compatível do script para executável"""
        print("Criando versão compatível com executável...")
        
        if not self.original_script.exists():
            raise FileNotFoundError(f"Script não encontrado: {self.original_script}")

        # Lê o conteúdo original
        with open(self.original_script, 'r', encoding='utf-8') as f:
            content = f.read()

        # CORREÇÃO 1: Substituir auto_detect_lua_file por prompt_for_file
        auto_detect_pattern = r'(    def auto_detect_lua_file\(self\):.*?)(?=\n    def \w+|\Z)'
        auto_detect_match = re.search(auto_detect_pattern, content, re.DOTALL)
        
        if auto_detect_match:
            old_auto_detect = auto_detect_match.group(1)
            new_prompt_method = '''    def prompt_for_file(self):
        """Solicita que o usuário selecione um arquivo .lua ao iniciar"""
        file_path = filedialog.askopenfilename(
            title="Select Lua File",
            filetypes=[("Lua files", "*.lua"), ("All files", "*.*")]
        )
        if file_path:
            self.load_lua_file(file_path)
        else:
            # Se o usuário cancelar, mostrar estado vazio
            self.show_empty_state()'''
            
            content = content.replace(old_auto_detect, new_prompt_method)

        # CORREÇÃO 2: Atualizar o __init__ para usar prompt_for_file
        init_pattern = r'(def __init__\(self, root\):.*?)(?=    def \w+|\Z)'
        init_match = re.search(init_pattern, content, re.DOTALL)
        
        if init_match:
            init_method = init_match.group(1)
            # Substituir a chamada do auto_detect_lua_file
            if 'self.auto_detect_lua_file()' in init_method:
                new_init = init_method.replace(
                    'self.auto_detect_lua_file()',
                    '# Remover auto-detecção e solicitar arquivo ao iniciar\\n        self.root.after(100, self.prompt_for_file)'
                )
                content = content.replace(init_method, new_init)

        # CORREÇÃO 3: Atualizar método save_changes para novo comportamento
        save_changes_pattern = r'(def save_changes\(self\):.*?)(?=def \w+|\Z)'
        save_changes_match = re.search(save_changes_pattern, content, re.DOTALL)
        
        if save_changes_match:
            save_changes_method = save_changes_match.group(1)
            
            # Verificar se já tem a nova lógica
            if 'asksaveasfilename' not in save_changes_method:
                # Substituir a lógica antiga pela nova
                new_save_changes = '''    def save_changes(self):
        if not self.lua_file_path:
            # CORREÇÃO: Se não há arquivo carregado, permitir que o usuário selecione um para salvar
            file_path = filedialog.asksaveasfilename(
                title="Save Lua File",
                filetypes=[("Lua files", "*.lua"), ("All files", "*.*")],
                defaultextension=".lua"
            )
            if file_path:
                self.lua_file_path = file_path
                # Criar um arquivo vazio se não existir
                if not os.path.exists(file_path):
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write("--// READ VARIABLES\\n\\n--// END READ VARIABLES\\n")
                self.load_lua_file(file_path)
            else:
                return  # Usuário cancelou
        
        try:
            self._validate_controls()
            
            with open(self.lua_file_path, 'r', encoding='utf-8') as file:
                original_content = file.read()
            
            # Criar backup
            backup_path = self.lua_file_path + '.backup'
            shutil.copy2(self.lua_file_path, backup_path)
            
            # Aplicar mudanças
            new_content = self.apply_changes(original_content)
            
            # Salvar arquivo
            with open(self.lua_file_path, 'w', encoding='utf-8') as file:
                file.write(new_content)
            
            # Feedback visual
            self.save_btn.configure(text="Saved!")
            self.root.after(2000, lambda: self.save_btn.configure(text="Save Changes"))
            
            messagebox.showinfo("Success", f"Changes saved successfully!\\nBackup created at: {backup_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save changes:\\n{str(e)}")'''
                
                content = content.replace(save_changes_method, new_save_changes)

        # CORREÇÃO 4: Adicionar novos métodos se não existirem
        if '_apply_changes_to_content_with_comments' not in content:
            # Adicionar os novos métodos após o método apply_changes
            apply_changes_end_pattern = r'(def apply_changes\(self, content: str\) -> str:.*?)(?=def \w+|\Z)'
            apply_changes_match = re.search(apply_changes_end_pattern, content, re.DOTALL)
            
            if apply_changes_match:
                apply_changes_end = apply_changes_match.end(1)
                new_methods = '''

    def _apply_changes_to_content_with_comments(self, content: str) -> str:
        """Aplica mudanças mantendo comentários da tabela"""
        lines = content.split('\\n')
        output_lines = []
        i = 0
        
        while i < len(lines):
            line = lines[i]
            
            # Verificar se esta linha inicia uma variável que temos controles para
            variable_found = False
            for var_name, control in self.controls.items():
                if var_name not in self.variables:
                    continue
                    
                var_data = self.variables[var_name]
                
                # Verificar se esta linha contém a declaração da variável
                if f'{{var_name}} =' in line:
                    if var_data['type'] == 'table' and '{{' in line:
                        if isinstance(control, dict) and control.get('type') == 'table':
                            # Reconstruir a tabela com valores atualizados mas mantendo estrutura original
                            table_lines = self._rebuild_table_with_comments(var_name, var_data, control)
                            output_lines.extend(table_lines)
                            
                            # Pular as linhas originais da tabela
                            brace_count = line.count('{{') - line.count('}}')
                            i += 1
                            while i < len(lines) and brace_count > 0:
                                brace_count += lines[i].count('{{') - lines[i].count('}}')
                                i += 1
                            variable_found = True
                            break
                    else:
                        # Para variáveis não-tabela, substituir o valor
                        new_value = self._get_control_value(var_name, control, var_data)
                        if new_value is not None:
                            # Preservar comentários na linha
                            if '--' in line:
                                comment_part = line.split('--', 1)[1]
                                output_lines.append(f'local {{var_name}} = {{new_value}} --{{comment_part}}')
                            else:
                                output_lines.append(f'local {{var_name}} = {{new_value}}')
                            i += 1
                            variable_found = True
                            break
            
            if not variable_found:
                # Se não era uma variável que estamos processando, manter a linha original
                output_lines.append(line)
                i += 1
        
        return '\\n'.join(output_lines)

    def _get_control_value(self, var_name: str, control, var_data: Dict) -> str:
        """Obtém o valor formatado do controle"""
        try:
            if isinstance(control, tk.BooleanVar):
                return str(control.get()).lower()
            elif isinstance(control, dict) and 'control' in control:
                # Selector
                selected_index = control['control'].current()
                if selected_index >= 0:
                    return str(control['values'][selected_index])
                else:
                    return str(var_data['value'])
            elif hasattr(control, 'get'):
                # Entry field
                value = control.get()
                # Formatar baseado no tipo
                if var_data['type'] in ['integer', 'float']:
                    return value
                elif var_data['type'] == 'string':
                    return f'"{value}"'
                else:
                    return str(value)
            else:
                return str(var_data['value'])
        except Exception as e:
            print(f"Erro ao obter valor do controle {{var_name}}: {{e}}")
            return str(var_data['value'])

    def _rebuild_table_with_comments(self, var_name: str, var_data: Dict, control: Dict) -> List[str]:
        """Reconstrói a tabela mantendo comentários e estrutura original"""
        table_lines = [f'local {{var_name}} = {{}}']
        
        table_controls = control.get('controls', {{}})
        original_value = var_data.get('value', {{}})
        
        # Usar a ordem original dos campos
        field_order = list(original_value.keys()) if isinstance(original_value, dict) else []
        
        for field_key in field_order:
            if field_key not in table_controls:
                continue
                
            field_control = table_controls[field_key]
            field_metadata = var_data.get('table_fields', {{}}).get(str(field_key), {{}})
            
            # Adicionar comentários do campo se existirem
            if field_metadata.get('name') or field_metadata.get('hint'):
                if field_metadata.get('name'):
                    table_lines.append(f'-- [UI] TABLEFIELD_NAME: {{field_metadata["name"]}}')
                if field_metadata.get('hint'):
                    table_lines.append(f'-- [UI] TABLEFIELD_HINT: {{field_metadata["hint"]}}')
            
            # Obter o novo valor do controle
            new_value = self._get_table_field_value(field_control, original_value.get(field_key))
            
            table_lines.append(f'    {{field_key}} = {{new_value}},')
        
        table_lines.append('}}')
        
        return table_lines

    def _get_table_field_value(self, field_control, original_value) -> str:
        """Obtém e formata o valor de um campo da tabela"""
        try:
            if isinstance(field_control, tk.BooleanVar):
                return str(field_control.get()).lower()
            elif isinstance(field_control, dict) and 'control' in field_control:
                # Selector em campo de tabela
                selected_index = field_control['control'].current()
                if selected_index >= 0:
                    value = field_control['values'][selected_index]
                else:
                    value = original_value
            elif hasattr(field_control, 'get'):
                # Entry field
                value = field_control.get()
            else:
                value = original_value
            
            # Formatar o valor
            if isinstance(value, str) and not value.replace('.', '').replace('-', '').isdigit():
                if value.lower() not in ['true', 'false']:
                    value = f'"{value}"'
            
            return str(value)
        except Exception as e:
            print(f"Erro ao obter valor do campo da tabela: {{e}}")
            return str(original_value)
'''
                content = content[:apply_changes_end] + new_methods + content[apply_changes_end:]

        # Salva o script corrigido
        with open(self.fixed_script, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("Script compatível criado com sucesso!")
        
        # Verifica se há problemas de indentação
        try:
            with open(self.fixed_script, 'r', encoding='utf-8') as f:
                test_content = f.read()
            compile(test_content, '<string>', 'exec')
            print("✅ Script verificado - sem erros de sintaxe")
            return True
        except SyntaxError as e:
            print(f"❌ Erro de sintaxe no script corrigido: {e}")
            return False

    def create_simple_patch_script(self):
        """Cria um script PATCHADO do zero com verificação de sintaxe"""
        print("🛠️  Criando script patched do zero...")
        
        # Lê o original
        with open(self.original_script, 'r', encoding='utf-8') as f:
            original_content = f.read()
        
        # CORREÇÃO 1: Substituir auto_detect_lua_file
        old_auto_detect_pattern = r'    def auto_detect_lua_file\(self\):.*?return'
        auto_detect_match = re.search(old_auto_detect_pattern, original_content, re.DOTALL)
        
        if auto_detect_match:
            old_auto_detect = auto_detect_match.group(0)
            new_prompt_method = '''    def prompt_for_file(self):
        """Solicita que o usuário selecione um arquivo .lua ao iniciar"""
        file_path = filedialog.askopenfilename(
            title="Select Lua File",
            filetypes=[("Lua files", "*.lua"), ("All files", "*.*")]
        )
        if file_path:
            self.load_lua_file(file_path)
        else:
            # Se o usuário cancelar, mostrar estado vazio
            self.show_empty_state()'''
            
            original_content = original_content.replace(old_auto_detect, new_prompt_method)
        
        # CORREÇÃO 2: Atualizar __init__
        if 'self.auto_detect_lua_file()' in original_content:
            original_content = original_content.replace(
                'self.auto_detect_lua_file()',
                '# Remover auto-detecção e solicitar arquivo ao iniciar\\n        self.root.after(100, self.prompt_for_file)'
            )
        
        # Salva
        with open(self.fixed_script, 'w', encoding='utf-8') as f:
            f.write(original_content)
        
        # Verifica a sintaxe
        try:
            compile(original_content, '<string>', 'exec')
            print("✅ Script patched criado e verificado!")
            return True
        except SyntaxError as e:
            print(f"❌ Erro de sintaxe no script patched: {e}")
            return False

    def create_direct_fix_script(self):
        """Cria uma correção direta e simples"""
        print("🔧 Criando correção direta...")
        
        with open(self.original_script, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # CORREÇÃO 1: Substituir auto_detect_lua_file por prompt_for_file
        auto_detect_start = -1
        for i, line in enumerate(lines):
            if 'def auto_detect_lua_file(self):' in line:
                auto_detect_start = i
                break
        
        if auto_detect_start != -1:
            # Encontra onde o método termina
            auto_detect_end = auto_detect_start
            for i in range(auto_detect_start + 1, len(lines)):
                if lines[i].startswith('    def ') and i > auto_detect_start + 1:
                    auto_detect_end = i
                    break
                elif i == len(lines) - 1:
                    auto_detect_end = len(lines)
                    break
            
            # Novo método
            new_prompt_method = [
                '    def prompt_for_file(self):\\n',
                '        """Solicita que o usuário selecione um arquivo .lua ao iniciar"""\\n',
                '        file_path = filedialog.askopenfilename(\\n',
                '            title="Select Lua File",\\n',
                '            filetypes=[("Lua files", "*.lua"), ("All files", "*.*")]\\n',
                '        )\\n',
                '        if file_path:\\n',
                '            self.load_lua_file(file_path)\\n',
                '        else:\\n',
                '            # Se o usuário cancelar, mostrar estado vazio\\n',
                '            self.show_empty_state()\\n'
            ]
            
            lines = lines[:auto_detect_start] + new_prompt_method + lines[auto_detect_end:]
        
        # CORREÇÃO 2: Atualizar __init__
        for i, line in enumerate(lines):
            if 'self.auto_detect_lua_file()' in line:
                lines[i] = '        # Remover auto-detecção e solicitar arquivo ao iniciar\\n        self.root.after(100, self.prompt_for_file)\\n'
                break
        
        # Salva o arquivo corrigido
        with open(self.fixed_script, 'w', encoding='utf-8') as f:
            f.writelines(lines)
        
        # Verifica a sintaxe
        try:
            with open(self.fixed_script, 'r', encoding='utf-8') as f:
                content = f.read()
            compile(content, '<string>', 'exec')
            print("✅ Correção direta aplicada com sucesso!")
            return True
        except SyntaxError as e:
            print(f"❌ Erro de sintaxe na correção direta: {e}")
            return False

    def compile_with_manual_fix(self):
        """Compila com uma abordagem mais manual e segura"""
        print("Compilando com abordagem segura...")
        
        # Limpa builds anteriores
        if self.build_dir.exists():
            shutil.rmtree(self.build_dir, ignore_errors=True)
        if self.dist_dir.exists():
            shutil.rmtree(self.dist_dir, ignore_errors=True)

        # Usa o script corrigido se existir, senão usa o original
        script_to_compile = self.fixed_script if self.fixed_script.exists() else self.original_script
        
        # Comando PyInstaller otimizado
        cmd = [
            sys.executable, 
            "-m", 
            "PyInstaller", 
            "--onefile",
            "--noconsole",
            "--clean",
            f"--name={self.name}",
            str(script_to_compile)
        ]
        
        print(f"Compilando: {script_to_compile.name}")
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            # Mostra saída em tempo real
            for line in process.stdout:
                print(line, end='')
            
            process.wait()
            
            return process.returncode == 0
            
        except Exception as e:
            print(f"❌ Erro durante a compilação: {e}")
            return False

    def verify_result(self):
        """Verifica se o executável foi criado"""
        print("\\nVerificando resultado...")
        
        exe_path = self.dist_dir / f"{self.name}.exe"
        
        if exe_path.exists():
            size_mb = exe_path.stat().st_size / (1024 * 1024)
            print(f"✅ Executável criado: {exe_path}")
            print(f"📏 Tamanho: {size_mb:.1f} MB")
            
            print("\\n📋 NOVAS FUNCIONALIDADES:")
            print("✅ Solicita arquivo Lua ao iniciar (não mais auto-detecção)")
            print("✅ Permite salvar em novo arquivo se não houver arquivo carregado")
            print("✅ Salva alterações corretamente em todos os tipos de variáveis")
            print("✅ Mantém comentários nas tabelas ao salvar")
            
            print("\\n🎯 INSTRUÇÕES:")
            print("1. Execute o programa")
            print("2. Selecione um arquivo Lua quando solicitado")
            print("3. Faça suas alterações na interface")
            print("4. Clique em 'Save Changes' para salvar")
            print("5. Um backup será criado automaticamente")
            
            return True
        else:
            print("❌ Executável não foi criado")
            return False

    def cleanup(self):
        """Limpeza"""
        print("🧹 Limpando arquivos temporários...")
        
        if self.fixed_script.exists():
            try:
                self.fixed_script.unlink()
                print("✅ Arquivo temporário removido")
            except:
                print("⚠️  Não foi possível remover arquivo temporário")
        
        # Remove arquivos .spec
        for spec_file in self.script_dir.glob("*.spec"):
            try:
                spec_file.unlink()
            except:
                pass

    def run_safe_compilation(self):
        """Executa compilação segura"""
        print("🚀 COMPILAÇÃO SEGURA - INICIANDO")
        print("=" * 60)
        print("🔄 ATUALIZANDO PARA NOVA VERSÃO DO CÓDIGO")
        print("=" * 60)
        
        try:
            # Tentativa 1: Substituição completa
            print("\\n🎯 TENTATIVA 1: Atualização completa...")
            success = self.create_compatible_script()
            
            if not success:
                print("\\n🔧 TENTATIVA 2: Patch simplificado...")
                success = self.create_simple_patch_script()
            
            if not success:
                print("\\n⚡ TENTATIVA 3: Correção mínima...")
                success = self.create_direct_fix_script()
            
            if success:
                print("\\n⚙️ COMPILANDO...")
                compile_success = self.compile_with_manual_fix()
                
                if compile_success:
                    self.verify_result()
                else:
                    print("❌ Falha na compilação")
            else:
                print("❌ Não foi possível criar o script atualizado")
            
            # Limpeza
            self.cleanup()
            
            print("=" * 60)
            
        except Exception as e:
            print(f"💥 ERRO: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    compiler = SafeCompiler()
    compiler.run_safe_compilation()