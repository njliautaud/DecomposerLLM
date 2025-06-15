package ghidra.llm.integration;

import docking.ComponentProvider;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class LLMPanel extends ComponentProvider {
    private JPanel mainPanel;
    private JTextArea queryArea;
    private JTextArea responseArea;
    private JComboBox<String> modelSelector;
    private JButton sendButton;
    private Program currentProgram;

    public LLMPanel(ProgramPlugin plugin) {
        super(plugin.getTool(), "LLM Integration", plugin.getName());
        buildPanel();
    }

    private void buildPanel() {
        mainPanel = new JPanel(new BorderLayout());
        
        // Model selection
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        modelSelector = new JComboBox<>(new String[]{"gemini-pro", "gemini-pro-vision"});
        topPanel.add(new JLabel("Model:"));
        topPanel.add(modelSelector);
        mainPanel.add(topPanel, BorderLayout.NORTH);

        // Query area
        queryArea = new JTextArea(5, 40);
        queryArea.setLineWrap(true);
        queryArea.setWrapStyleWord(true);
        JScrollPane queryScroll = new JScrollPane(queryArea);
        mainPanel.add(queryScroll, BorderLayout.CENTER);

        // Response area
        responseArea = new JTextArea(10, 40);
        responseArea.setLineWrap(true);
        responseArea.setWrapStyleWord(true);
        responseArea.setEditable(false);
        JScrollPane responseScroll = new JScrollPane(responseArea);
        mainPanel.add(responseScroll, BorderLayout.SOUTH);

        // Send button
        sendButton = new JButton("Send to LLM");
        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendToLLM();
            }
        });
        topPanel.add(sendButton);

        setVisible(true);
    }

    private void sendToLLM() {
        String query = queryArea.getText();
        String selectedModel = (String) modelSelector.getSelectedItem();
        
        if (query.isEmpty()) {
            Msg.showWarn(this, mainPanel, "Empty Query", "Please enter a query for the LLM.");
            return;
        }

        // TODO: Implement actual LLM communication
        responseArea.setText("Processing query: " + query + "\nUsing model: " + selectedModel);
    }

    public void programActivated(Program program) {
        this.currentProgram = program;
        // TODO: Update UI based on program context
    }

    public void programDeactivated(Program program) {
        if (this.currentProgram == program) {
            this.currentProgram = null;
        }
    }

    public void programClosed(Program program) {
        if (this.currentProgram == program) {
            this.currentProgram = null;
        }
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }
} 