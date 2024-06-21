import gradio as gr
from TwoFish import TwoFish_decrypt, TwoFish_encrypt

with open('Key.txt', 'r') as f:
    keys = f.readlines()

css = """
#warning {background-color: #FFCCCB}
.feedback textarea {font-size: 30px !important}
"""

with gr.Blocks(css=css, theme=gr.themes.Default(spacing_size="sm", text_size="lg")) as demo:
    with gr.Row():
        key_input = gr.Dropdown(choices=keys, label="Select Keys:", scale = 1)
    mode_input = gr.Radio(choices=["ECB", "CBC"], label="Select Mode:", scale=2)
    with gr.Row():
        with gr.Column():
            plaintext_input = gr.Textbox(label="Enter Plaintext:", show_copy_button=True, lines=2)
            encrypt_button = gr.Button("Encrypt", variant="primary")
            encrypt_output = gr.Textbox(label="Encrypted Output", show_copy_button=True, lines=2)
        with gr.Column():
            ciphertext_input = gr.Textbox(label="Enter Ciphertext:", show_copy_button=True, lines=2)
            decrypt_button = gr.Button("Decrypt", variant="primary", min_width=100)
            decrypt_output = gr.Textbox(label="Decrypted Output", show_copy_button=True, lines=2)

    encrypt_button.click(TwoFish_encrypt, inputs=[plaintext_input, key_input, mode_input], outputs=encrypt_output)
    decrypt_button.click(TwoFish_decrypt, inputs=[ciphertext_input, key_input, mode_input], outputs=decrypt_output)


if __name__ == "__main__":
    demo.launch()
